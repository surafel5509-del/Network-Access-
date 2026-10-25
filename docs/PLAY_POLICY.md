# Google Play policy notes

> The specification requires flagging every feature that risks Play Store
> rejection and proposing a compliant alternative. This is that document.

## Permission inventory (this build)

| Permission | Why | Policy requirement | Status |
|---|---|---|---|
| `ACCESS_FINE_LOCATION` / `ACCESS_COARSE_LOCATION` | Wi-Fi scan results on Android 8+ | Prominent in-use disclosure + Data Safety declaration; no background use | ✅ declared, no background location |
| `ACCESS_WIFI_STATE` / `CHANGE_WIFI_STATE` | Read scan results, trigger scans | Normal protection | ✅ |
| `CHANGE_WIFI_MULTICAST_STATE` | SSDP discovery | Normal, low risk | ✅ |
| `BLUETOOTH_SCAN` / `BLUETOOTH_CONNECT` | Future BLE engine | Nearby-devices declaration; `neverForLocation` set | ✅ declared for Phase 5 |
| `NFC` | Future NDEF read | Normal | ✅ |
| `BIND_VPN_SERVICE` (service permission) | Packet capture | **VPN Service permission**: prominent disclosure, privacy policy, core functionality justification | ✅ gate + legal notice; see below |
| `FOREGROUND_SERVICE` + `FOREGROUND_SERVICE_DATA_SYNC` | Capture service | FGS type declaration + Play Console declaration | ⚠️ review before release (use `connectedDevice` or `specialUse` if more appropriate for VPN) |
| `POST_NOTIFICATIONS` | Capture / alert notifications | Runtime request with clear value | ✅ requested at startup |
| `USE_BIOMETRIC` | Sensitive action confirmation | Normal | ✅ |
| `INTERNET` | User-initiated scans + opt-in RDAP | Normal | ✅ |

**Not requested (deliberately):** `READ_PHONE_STATE`,
`READ_PRIVILEGED_PHONE_STATE`, `QUERY_ALL_PACKAGES`, `PACKAGE_USAGE_STATS`,
`ACCESS_BACKGROUND_LOCATION`, `WRITE_SETTINGS`, `REQUEST_DELETE_PACKAGES`,
`SYSTEM_ALERT_WINDOW`, `BIND_ACCESSIBILITY_SERVICE`.

## High-risk features and compliant alternatives

### 1. A "Wi-Fi password cracker" — REJECTED as specified
An app that recovers WPA keys from networks in range is an enabling tool for
unauthorised access and would be rejected under the **Device and Network Abuse**
policy (and likely malware policy). **Compliant alternative shipped:** an
offline, consent-gated WPA-PSK *educational lab* operating only on synthetic or
user-imported handshakes, with no capture capability. See
[SECURITY_LAB.md](SECURITY_LAB.md).

### 2. Port scanner — MEDIUM RISK
Allowed for network administration, but the store listing must clearly describe
it as an audit tool for networks you own, and the app must show an in-app
consent dialog (done). **Do not** bundle target lists for third-party
infrastructure, and do not implement SYN stealth scans on-device (they require
root and look like attack tooling).

### 3. VpnService capture — HIGH RISK
Play requires: (a) a prominent disclosure before the OS VPN consent dialog,
(b) a privacy policy explaining what is collected, (c) the VPN must be core to
the app's functionality, (d) no redirection of traffic to third parties.
**Our design:** VpnService is used exclusively for local packet analysis; no
traffic is sent to any server; a lab subnet only. Add an explicit in-app screen
before `VpnService.prepare()` (Phase 4 follow-up — currently the consent dialog
covers it).

### 4. MITM / HTTPS interception proxy — VERY HIGH RISK
Rejected if it can silently intercept other apps' HTTPS. **Compliant
alternative:** not implemented. If added: user-installed CA only (never a
bundled private key), per-session consent, local loopback proxy only, HAR
exports encrypted, and no pinning bypass. Keep it out of the default build.

### 5. Root/Shizuku features — HIGH RISK
Play's **Device and Network Abuse** policy forbids apps that exploit root to
modify system behaviour without clear user consent. **Alternative:** root-optional
design (done), explicit requirement chips, warning dialogs, and root features in
a separate, clearly-labelled build flavour if necessary.

### 6. QUERY_ALL_PACKAGES (app audit) — HIGH RISK
Requires a Play Console declaration and is only granted for apps whose core
function is package discovery (file managers, antivirus). **Alternative:**
use `PackageManager` with explicit `<queries>` entries for known tracker SDK
signatures, or an accessibility-free, user-selected-app workflow. The
foundation build returns an explicit "not yet collected" finding instead.

### 7. Accessibility service — VERY HIGH RISK
Frequently abused. **Alternative:** do not use it. Device audit *reads* the
enabled-services setting and warns about abuse rather than becoming one.

### 8. Offline messaging / mesh (Phase 6) — MEDIUM
If it looks like a general VPN or proxy, it needs the same VPN disclosure.
Prefer Wi-Fi Direct / BLE with no VPN involvement.

### 9. Servers (HTTP/FTP/SSH/WebDAV) — MEDIUM
A local FTP/SSH server with weak default credentials could be flagged as a
backdoor. **Alternative:** generate a random token at first start, bind to
loopback or the LAN only behind a biometric gate, show active clients, and
never enable by default.

### 10. Data Safety form
Declare: no data collected, no data shared, data encrypted in transit (N/A) and
at rest (yes), deletion mechanism (Settings → Delete all local data). If online
features are enabled, declare "Network info — ephemeral, user-initiated, not
linked to identity".

## Release checklist (before any Play upload)

- [ ] Bump `targetSdk` to the current Play requirement (currently 35).
- [ ] Add real certificate pins for opt-in endpoints.
- [ ] Encrypt pcap files (P0 in the threat model).
- [ ] Add runtime signature/Play Integrity check.
- [ ] Add the pre-VPN disclosure screen.
- [ ] Complete the Data Safety form and the sensitive-permission declarations.
- [ ] Submit a testing-instructions video showing the legal notice + consent.
