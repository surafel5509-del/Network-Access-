# ADR-0005 — SQLCipher + Android Keystore + EncryptedFile

**Status:** Accepted · **Date:** 2026-10-25

## Context
The app stores an audit log, score history and reports that could reveal a
user's network topology. Plain Room/SharedPreferences would expose them on a
rooted device, through backups or via a stolen handset.

## Decision
- Room is opened with `net.zetetic.database.sqlcipher.SupportOpenHelperFactory`
  (`net.zetetic:sqlcipher-android:4.5.5`). Native `libsqlcipher` is loaded in
  `SentinelNetApp` and in `AppModule.provideDatabase()`.
- A random 32-byte DB passphrase is generated once and stored in
  `EncryptedSharedPreferences` protected by a Keystore `MasterKey`
  (AES-256-GCM, StrongBox where available for export keys).
- Exports go through `androidx.security.crypto.EncryptedFile`.
- `allowBackup=false` and `data_extraction_rules.xml` exclude all app data from
  cloud/device transfer.

## Consequences
- ✅ Data at rest is encrypted; no passphrase in source or logs.
- ✅ StrongBox degrades gracefully when unavailable.
- ❌ Losing the Keystore key (factory reset / key invalidation) makes the DB
  unreadable — acceptable for an audit tool; users can export first.
- ⚠️ Open item (P0): pcap files are currently written plain to
  `filesDir/captures`; switch to EncryptedFile before release.
