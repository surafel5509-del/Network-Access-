# sentinel-parser (native)

Dependency-free Rust crate implementing the packet **metadata** hot path:
IPv4 / TCP / UDP / ICMP dissection, DNS question extraction (including RFC 1035
compression pointers), application classification, and pcap framing.

It mirrors the Kotlin reference implementation in `core/pure/.../pcap`, which is
used as the oracle by the conformance suite. Payload bytes are never copied out
of the input buffer.

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release   # produces libs for arm64-v8a / x86_64 via scripts/build-native.sh
```

**JNI status (Phase 4):** the crate currently exposes a safe Rust API only. The
JNI facade (`SentinelNative.kt` + `jni.rs`) and the CMake/`cargo-ndk` build for
`arm64-v8a`, `armeabi-v7a` and `x86_64` are delivered in the packet-capture
phase. Until then, VpnService uses the Kotlin parser — behaviour is identical,
just slower at very high packet rates. See ADR-0003.
