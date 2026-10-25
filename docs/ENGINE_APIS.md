# Engine API reference

Every engine implements `SentinelEngine` (`:engine:api`):

```kotlin
interface SentinelEngine {
    val id: String
    val displayName: String
    val requiredCapability: Capability
    fun status(): EngineStatus   // available? requirement? reason?
}
```

`EngineStatus` reports `NONE`, `PERMISSION`, `BIOMETRIC`, `ROOT`, `SHIZUKU`,
`HARDWARE`, `CONSENT` or `NOT_IMPLEMENTED`. The UI shows this as a chip and
refuses to launch unavailable engines — this is the root-optional rule.

For each module below: **interface → implementation plan → test plan → Play policy**.

---

## A. Discovery engines

### A1 `WifiEngine` — ✅ implemented (`AndroidWifiEngine`)
```kotlin
suspend fun scan(): Result<List<WifiNetwork>>
fun observeNetworks(): Flow<List<WifiNetwork>>
fun recommendChannel(band: Band): ChannelRecommendation
suspend fun captivePortalCheck(): Boolean
```
*Plan:* `WifiManager.startScan()` + `scanResults`, capability-string parser,
`ChannelAdvisor` congestion model, `WifiSecurityAuditor`, `OuiLookup`.
*Tests:* `WifiCapabilitiesParserTest` (SAE/EAP/OWE/WEP/open), conformance suite
for channel math, vendor OUI and evil-twin detection. Instrumented: verify
`status()` reports a missing-location-permission requirement.
*Play policy:* Wi-Fi scanning requires `ACCESS_FINE_LOCATION` with a prominent
in-use disclosure; declare in the Data Safety form. No background location.

### A2–A6 BLE / NFC / Cellular / Wi-Fi Direct / Ethernet — 🟡 `PlannedEngine`
Interfaces exist; implementations return `NOT_IMPLEMENTED`.
*Plan (Phase 5):* `BluetoothLeScanner` (never derive location from BLE scans —
use `neverForLocation`), `NfcAdapter` + NDEF tech enumeration,
`TelephonyManager.allCellInfo` filtered to non-sensitive fields (no IMSI/IMEI),
`WifiP2pManager`, `UsbManager`/`EthernetManager`.
*Tests:* Robolectric + fake system services; assert no identifier APIs are called.
*Play policy:* `BLUETOOTH_SCAN` / `BLUETOOTH_CONNECT` need a nearby-devices
declaration; `READ_PHONE_STATE` must be avoided — prefer `SubscriptionInfo`
non-sensitive fields. NFC is low-risk.

### A7 `DeviceDiscoveryEngine` — ✅ implemented
```kotlin
fun discover(subnetCidr: String, consent: ConsentRequest): Flow<DiscoveredDevice>
suspend fun fingerprint(device: DiscoveredDevice): DiscoveredDevice
```
*Tests:* /24 expansion limits, ARP parsing, SSDP timeout, passive TTL OS guess.
*Play policy:* local network scanning is allowed but must be described in the
store listing as a security-audit feature with an in-app consent dialog.

## B. Scanning

### B1/B2 `PortScanEngine` — ✅ TCP Connect only
```kotlin
fun scan(config: ScanConfig, consent: ConsentRequest): Flow<PortResult>
```
`ScanConfig(target, ports, concurrency, connectTimeoutMs, grabBanner, inspectTls)`.
*Plan:* `Socket.connect()` with a `Semaphore`; banner grab; TLS peer certificate
subject via `SSLSocket`; `CveHintMatcher` for passive hints.
*Tests:* `BannerGrabberTest`; loopback integration test against a local
`ServerSocket`; conformance for `PortRisk` scoring.
*Play policy:* a port scanner is dual-use. Must be framed as auditing *your own*
network, gated by consent, and must not ship a port list targeting third-party
infrastructure. SYN/FIN/NULL/XMAS scans need root and are deferred.

## C. Capture

### C1/C2 `CaptureEngine` — ✅ lab-mode VpnService; 🟡 transparent forwarding
```kotlin
fun start(consent: ConsentRequest): Flow<String>
fun stop(); fun isRunning(): Boolean; fun exportPcap(): File?
```
*Plan:* `VpnService.Builder` → raw fd → `PacketParser` → `FlowTracker` →
`PcapWriter` (LINKTYPE_RAW). Phase 4 adds tun2socks forwarding + Rust JNI.
*Tests:* conformance suite parses synthetic IPv4/IPv6/TCP/UDP/DNS/Ethernet
frames, pcap headers, DNS compression loops and malformed packets.
*Play policy:* `VpnService` is a sensitive permission. Requires a prominent
in-app disclosure, a privacy policy, and a clear statement that traffic is
analysed locally. Apps using VPN for unrelated purposes are rejected — here it
is core functionality.

### C3 MITM proxy — 🔴 not implemented
*Plan (Phase 4):* explicit consent on every start, user-installed CA via the OS
certificate installer (never programmatic), HAR export, no HTTPS interception
without a second warning.
*Play policy:* **high rejection risk.** A local MITM proxy must never be
bundled with a pre-generated CA private key, must not target third-party apps
by default, and cannot be used to bypass certificate pinning. Deferred until a
compliance review.

## D. Audit

### D1/D2/D3 `SecurityAuditEngine` — ✅ implemented
```kotlin
suspend fun runFullAudit(): Result<SecurityScore>
suspend fun networkAudit(): List<Finding>
suspend fun deviceAudit(): List<Finding>
suspend fun appAudit(): List<Finding>
```
*Tests:* score determinism/fingerprint, category weights, passive findings.
*Play policy:* root detection, user-CA enumeration and accessibility-service
review are defensive checks; no `QUERY_ALL_PACKAGES` yet (that permission needs
a policy declaration and is deferred to Phase 3 hardening).

### D6 `FirewallEngine` — 🟡 planned (Phase 3)
*Play policy:* another VpnService consumer; cannot coexist with capture without
a single shared VPN session. ADR-0004 documents the design.

## E–H. Tools, servers, messaging, device management

Interfaces exist in `:engine:api` (`NetworkToolsEngine`, `CryptoEngine`,
`AutomationEngine`, `ServerEngine`, `MessagingEngine`, `DeviceManagerEngine`).
`NetworkToolsEngineImpl` (ping, DNS, HTTP headers, RDAP) and the crypto tools
(pure Kotlin) are implemented. Traceroute, servers, scripting, mesh messaging
and APK backup are explicitly deferred — see [ROADMAP.md](ROADMAP.md).

*Play policy hotspots:* `QUERY_ALL_PACKAGES`, accessibility service,
`REQUEST_DELETE_PACKAGES`, `WRITE_SETTINGS`, VPN + server coexistence,
background location for geofenced automation. See [PLAY_POLICY.md](PLAY_POLICY.md).

## I. Reporting

`ReportBuilder` (pure Kotlin) emits `sentinelnet.report/1` JSON and CSV. The
security report wraps a stable document in a SHA-256 chain-of-custody hash.
Tests cover escaping, reproducibility, UTC timestamps and CSV quoting.
PDF rendering via `PdfDocument` is Phase 8.
