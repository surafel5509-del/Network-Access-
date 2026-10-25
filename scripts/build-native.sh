#!/usr/bin/env bash
# Builds the Rust parser for Android ABIs. Requires cargo-ndk and the Android NDK.
# The foundation build does NOT require this: :core:pure provides the Kotlin parser.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../native/rust/sentinel-parser"
: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your NDK path}"
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ../../out/jniLibs build --release
echo "Native libraries written to native/out/jniLibs (gitignored)."
