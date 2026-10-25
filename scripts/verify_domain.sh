#!/usr/bin/env bash
# Compile and run the pure-Kotlin domain conformance suite WITHOUT Gradle or the
# Android SDK. Useful in air-gapped / minimal environments and in CI.
#
# Requirements: a JDK 17+ and a Kotlin 1.9.x compiler. The script finds either
#   (a) `kotlinc` on PATH,
#   (b) $SENTINEL_KOTLINC_LIB pointing at a Kotlin compiler `lib/` directory
#       (e.g. npm i kotlin-compiler@1.9.25 -> node_modules/kotlin-compiler/lib),
#   (c) ~/.cache/sentinelnet/kotlin-compiler/lib.
# If none is found it falls back to Gradle's :core:pure:conformance task.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="$ROOT/build/domain-verification"
mkdir -p "$OUT"

JAVA_BIN="${SENTINEL_JAVA:-}"
if [[ -z "$JAVA_BIN" ]]; then
  if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]]; then JAVA_BIN="$JAVA_HOME/bin/java"
  elif command -v java >/dev/null 2>&1; then JAVA_BIN="$(command -v java)"
  else echo "ERROR: no java found (set SENTINEL_JAVA)"; exit 2; fi
fi

KOTLINC="$(command -v kotlinc || true)"
KLIB="${SENTINEL_KOTLINC_LIB:-$HOME/.cache/sentinelnet/kotlin-compiler/lib}"

if [[ -n "$KOTLINC" ]]; then
  echo "==> using kotlinc: $KOTLINC"
  COMPILE() { "$KOTLINC" "$@"; }
  STDLIB=""
  for candidate in "$(dirname "$(readlink -f "$KOTLINC")")/../lib/kotlin-stdlib.jar" \
                   "/usr/share/kotlin/lib/kotlin-stdlib.jar"; do
    [[ -f "$candidate" ]] && STDLIB="$candidate" && break
  done
elif [[ -d "$KLIB" && -f "$KLIB/kotlin-compiler.jar" ]]; then
  echo "==> using compiler jars in $KLIB"
  CP="$KLIB/kotlin-compiler.jar:$KLIB/kotlin-stdlib.jar:$KLIB/kotlin-script-runtime.jar:$KLIB/trove4j.jar:$KLIB/kotlin-daemon-client.jar:$KLIB/kotlin-reflect.jar"
  COMPILE() { "$JAVA_BIN" -cp "$CP" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler "$@"; }
  STDLIB="$KLIB/kotlin-stdlib.jar"
else
  echo "==> no local Kotlin compiler; falling back to Gradle"
  exec ./gradlew :core:pure:conformance "$@"
fi

MAIN_SRCS=$(find core/pure/src/main/kotlin -name '*.kt' | sort)
TEST_SRCS=$(find core/pure/src/test/kotlin -name '*.kt' | sort)

echo "==> compiling :core:pure"
COMPILE -jvm-target 17 -d "$OUT/main.jar" $MAIN_SRCS
echo "==> compiling conformance suite"
COMPILE -jvm-target 17 -classpath "$OUT/main.jar${STDLIB:+:$STDLIB}" -d "$OUT/test.jar" $TEST_SRCS
echo "==> running conformance suite"
"$JAVA_BIN" -cp "$OUT/test.jar:$OUT/main.jar:$STDLIB" \
  com.sentinelnet.verification.ConformanceSuiteKt "$@"
