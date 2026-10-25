# Developer Guide

## 1. Prerequisites

- JDK 17, Android SDK with platform 35 + build-tools 35.0.0, Gradle 8.9
  (wrapper jar included), Kotlin 1.9.25.
- Optional: Rust 1.75+ and `cargo-ndk` for the native parser.
- Android Studio Ladybug or newer.

```bash
./gradlew :core:pure:conformance     # pure-Kotlin tests, no SDK required
./gradlew :app:testDebugUnitTest     # JVM unit tests
./gradlew :app:connectedDebugAndroidTest   # instrumented tests (device needed)
./gradlew :app:assembleDebug
./gradlew detekt :app:lintDebug
python3 scripts/verify_project.py
./scripts/verify_domain.sh           # same conformance suite on a bare JDK
(cd native/rust/sentinel-parser && cargo test)
```

`scripts/verify_domain.sh` needs `kotlinc` on PATH, or
`SENTINEL_KOTLINC_LIB` pointing at a Kotlin compiler `lib/` directory
(e.g. `npm install kotlin-compiler@1.9.25`), and `SENTINEL_JAVA`/`JAVA_HOME`.
It falls back to Gradle if neither is available.

## 2. Modules

```
:core:pure       pure JVM Kotlin — models, consent, domain, crypto, pcap, reporting
:core:android    Room/SQLCipher, Keystore, DataStore, EncryptedFile, M3 theme, DI
:engine:api      engine interfaces + PlannedEngine placeholders
:engine:wifi     AndroidWifiEngine, WifiCapabilitiesParser
:engine:scanner  TcpConnectScanner, AndroidDeviceDiscovery, NetworkToolsEngineImpl
:engine:capture  SentinelVpnService, VpnCaptureEngine
:engine:audit    audits, scoring, SecurityLabController
:app             Compose UI + ViewModels + Hilt bindings + resources
```

Dependency direction is documented in [ARCHITECTURE.md](ARCHITECTURE.md).
`scripts/verify_project.py` checks every module listed in `settings.gradle.kts`
has a build file and sources.

## 3. Adding a new engine (the checklist)

1. Add a `Capability` in `:core:pure` if the feature is invasive. Pick
   `requiresBiometric` deliberately.
2. Add an interface in `:engine:api` extending `SentinelEngine`. Add a
   `PlannedEngine` subclass so the UI can show it as "Planned".
3. Create a Gradle module (copy another engine's `build.gradle.kts`), add it to
   `settings.gradle.kts` and to `:app`'s dependencies.
4. Implement it with an `@Inject constructor`, calling
   `consentGate.guard(request) { ... }` inside the cold flow / suspend function.
   Never call system APIs directly from a Composable or ViewModel.
5. Bind it in `app/di/EngineBindings.kt`.
6. Add unit tests in the module and conformance checks in
   `core/pure/src/test/kotlin/.../ConformanceSuite.kt` for any pure logic.
7. Update `docs/ENGINE_APIS.md`, `docs/PLAY_POLICY.md` and
   `scripts/verify_project.py` invariants.
8. Add a Semgrep rule if the new engine has a new invasive entry point.

## 4. Consent contract (do not break)

```kotlin
// UI: one nonce per action
val nonce = ConsentRequests.newNonce()
// ConsentDialog(capability, target, nonce, ...) -> ConsentDecision(nonce = nonce)
// ViewModel:
val request = ConsentRequest(capability, nonce, target, actor, sessionId, decision)
// Engine (inside the cold flow):
val verdict = consentGate.guard(request) { doTheWork() }
```

Rules: never cache a decision, never reuse a nonce, never add a bypass overload
to the gate, never log raw packet payloads, never call `getImei()` /
`getSubscriberId()` / `Build.getSerial()`.

## 5. Data layer

`SentinelDatabase` is a Room DB opened with SQLCipher's
`SupportOpenHelperFactory` (artifact `net.zetetic:sqlcipher-android:4.5.5`).
The 32-byte passphrase is generated once and stored in
`EncryptedSharedPreferences` protected by an Android Keystore master key.
`System.loadLibrary("sqlcipher")` runs in `SentinelNetApp`'s init block and again
in `AppModule.provideDatabase()`.

The audit DAO is synchronous on purpose: `ConsentGate` writes an event *before*
the action, and callers are always on `Dispatchers.IO`. Room queries returning
`Flow` are used for UI observation only.

`exportSchema = true` requires a Room schema location. Before release add:
```kotlin
ksp { arg("room.schemaLocation", "$projectDir/schemas") }
```
and commit the generated schemas. Migrations must be explicit —
`fallbackToDestructiveMigration()` is acceptable only for v0.1 development.

## 6. Native parser

`native/rust/sentinel-parser` is dependency-free and has no `unsafe` in the
parser. To wire it up (Phase 4):

```bash
export ANDROID_NDK_HOME=/path/to/ndk
./scripts/build-native.sh     # cargo-ndk -> native/out/jniLibs (gitignored)
```
Then add a JNI facade (`SentinelNative.kt`) with a thin, bounds-checked
`external fun`, and replace `PacketParser.parse()` in `SentinelVpnService`.
Keep the Kotlin parser as the fallback and as the test oracle.

## 7. Release signing & CI

`.github/workflows/ci.yml` runs: domain conformance, Android unit tests + lint +
`assembleDebug`, Rust fmt/clippy/test, and the Python invariant check. To sign a
release build locally, create `keystore.properties` (gitignored):

```
storeFile=/path/to/release.jks
storePassword=...
keyAlias=sentinelnet
keyPassword=...
```
and add a `signingConfigs` block reading it; never commit the keystore. In CI,
inject the base64 keystore from secrets and decode it in the workflow.

Before release also add real SPKI certificate pins to `AppModule.provideOkHttpClient()`
(the foundation ships no placeholder pin, because a fake pin would break RDAP).

## 8. Test strategy

| Level | Tool | Where |
|---|---|---|
| Domain algorithms | self-contained conformance suite (85 checks) | `core/pure/src/test` |
| Engine unit | JUnit 5 + MockK | `engine/*/src/test`, `app/src/test` |
| UI | Compose test rule | `app/src/androidTest` |
| Native | `cargo test` + clippy | `native/rust` |
| Static | detekt, Android lint, Semgrep, `verify_project.py` | CI |
| Fuzz | planned (`cargo-fuzz`, randomised JVM packets) | Phase 4 |

Coverage target: >70 % for `:core:pure` (already fully exercised by the suite)
and all engine interfaces.

## 9. Common pitfalls

- **Do not** enable `buildFeatures.compose` on a module without setting
  `composeOptions.kotlinCompilerExtensionVersion`; all modules set 1.5.15 for
  Kotlin 1.9.25.
- `ScanResult.capabilities` is localised on some OEMs — parse uppercased ASCII
  tokens only (see `WifiCapabilitiesParser`).
- Android throttles `WifiManager.startScan()`; do not loop it.
- `InetAddress.isReachable()` may use TCP echo instead of ICMP on some devices;
  that is why discovery also reads `/proc/net/arp` and SSDP.
- `targetSdk` must be bumped to the current Play requirement before upload.
