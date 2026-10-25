# SentinelNet — Architecture

## 1. Layer diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│ Presentation (Jetpack Compose / Material 3)                          │
│   Onboarding · Dashboard · Wi-Fi · Scanner · Audit · Lab · Settings   │
│   ViewModel (StateFlow) — hiltViewModel()                            │
└───────────────────────────┬──────────────────────────────────────────┘
                            │  observes StateFlow, emits Intent
┌───────────────────────────▼──────────────────────────────────────────┐
│ Domain / Use-case layer (pure Kotlin, :core:pure)                     │
│   ConsentGate · SecurityScorer · ChannelAdvisor · WifiSecurityAuditor │
│   RogueApDetector · PortRisk · CveHintMatcher · WpaPskLab · Reports   │
└───────────────────────────┬──────────────────────────────────────────┘
                            │  stable engine interfaces (:engine:api)
┌───────────────────────────▼──────────────────────────────────────────┐
│ Engine layer (one Gradle module per engine)                           │
│   wifi · scanner · capture · audit · api (+ planned placeholders)     │
│   Every engine calls ConsentGate before an invasive operation.        │
└───────────────────────────┬──────────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────────┐
│ Android system APIs / native                                          │
│   WifiManager · ConnectivityManager · VpnService · NsdManager         │
│   TelephonyManager (non-sensitive only) · BluetoothLeScanner · Nfc     │
│   Rust `sentinel-parser` (Phase 4 JNI) or Kotlin reference parser     │
└───────────────────────────┬──────────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────────┐
│ Data (:core:android)                                                  │
│   Room + SQLCipher (AES-256) · DataStore · Android Keystore            │
│   EncryptedFile exports · append-only audit log                       │
└──────────────────────────────────────────────────────────────────────┘
```

## 2. Dependency rules (enforced by Gradle module boundaries)

1. `:core:pure` depends on **nothing** but the Kotlin stdlib + JDK. This is why
   it can be compiled and tested on a bare JVM (`scripts/verify_domain.sh`) and
   why the legal gate is portable/auditable.
2. `:engine:api` depends only on `:core:pure`. It contains no Android
   framework calls — interfaces, DTOs and status types.
3. Engine implementation modules depend on `:engine:api` + `:core:pure`.
   They **never** depend on `:app`, and they never import another engine's
   implementation (only interfaces).
4. `:core:android` depends only on `:core:pure`. It does **not** depend on any
   engine (the `RequirementChip` composable lives in `:app` for that reason).
5. `:app` is the only module that depends on everything; it contains no
   Android system-API calls in screens/ViewModels (only `FileProvider`,
   `BiometricPrompt` and permission requests in the Activity/dialog).

## 3. The consent gate as a cross-cutting concern

`ConsentGate.guard()` is the *only* path to an invasive action. It is not an
annotation that can be forgotten: engines must pass a `ConsentRequest`
(containing a `ConsentDecision` produced by the single `ConsentDialog`),
and the gate returns a sealed `ConsentResult` that callers must handle.

```
UI                       ViewModel                 Engine              ConsentGate
 │ click "scan"             │                        │                     │
 ├─────────────────────────► newNonce()             │                     │
 │◄──── ConsentDialog ──────┤                        │                     │
 │ user checks 4 boxes +    │                        │                     │
 │ biometric + scope        │                        │                     │
 ├──── ConsentDecision ────►│                        │                     │
 │                          ├─ ConsentRequest ──────► scan(config, req)   │
 │                          │                        ├─ guard(req)────────►│
 │                          │                        │   • notice version  │
 │                          │                        │   • safe mode       │
 │                          │                        │   • nonce (single-use)
 │                          │                        │   • biometric       │
 │                          │                        │   • target scope    │
 │                          │                        │   • rate limit      │
 │                          │                        │◄── ALLOWED + audit ─┤
 │◄──── Flow<PortResult> ───┤◄──── results ─────────┤                     │
```

## 4. Concurrency & lifecycle

- All long-running work uses structured coroutines (`viewModelScope`,
  `coroutineScope`, `channelFlow`). Cold flows are used for scans so a
  cancelled screen cancels the scan.
- Capture and servers use foreground services with a persistent notification.
  `SentinelVpnService` runs its read loop on `Dispatchers.IO`.
- WorkManager is reserved for scheduled reports / CVE-feed refresh (Phase 8).
- Adaptive scanning: the Wi-Fi engine reads cached `scanResults` and lets the
  OS throttle `startScan()` — no busy loop, respecting the ~4 scans/2 min limit.

## 5. Data flows and privacy boundaries

| Data | Where it lives | Encrypted | Leaves device? |
|---|---|---|---|
| Audit events | Room (SQLCipher) | yes | only via explicit export |
| Wi-Fi scan results | in-memory StateFlow | n/a | no |
| Discoveries / port results | in-memory | n/a | only via explicit export |
| pcap files | `filesDir/captures` | EncryptedFile in Phase 4 | only via explicit share |
| Reports | `filesDir/exports` | EncryptedFile | only via explicit share |
| Settings | DataStore prefs | Keystore-backed prefs for secrets | no |
| DB passphrase | EncryptedSharedPreferences | Keystore AES-256-GCM | no |

**Never collected:** IMSI, IMEI, serial, advertising ID, phone number, contact
list, SMS, precise location history, raw packet payloads in logs.

## 6. Known limitations of this foundation build

- `SentinelVpnService` routes only a synthetic lab subnet (`10.222.222.0/24`)
  and does not forward packets. Real transparent capture needs a tun2socks
  relay (Phase 4). No real user traffic is intercepted today.
- Root/Shizuku paths, raw sockets, SYN/FIN/NULL/XMAS scans, MITM proxy, servers,
  messaging, BLE/NFC/Cellular, scripting and PDF reports are not implemented —
  their interfaces exist and their UI status is honestly "Planned".
- The Rust crate is compiled and tested in CI but not yet wired via JNI; the
  Kotlin parser is used at runtime (same grammar, verified against it).
- `targetSdk` is 35; bump to the current Play requirement before release.
