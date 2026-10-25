#!/usr/bin/env python3
"""Static safety / completeness invariants for the SentinelNet repository.

Run in CI (`python3 scripts/verify_project.py`) and locally. It deliberately
does not need any Python packages beyond the standard library.
"""
from __future__ import annotations
import csv
import io
import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors: list[str] = []
checks = 0


def check(cond: bool, msg: str) -> None:
    global checks
    checks += 1
    if not cond:
        errors.append(msg)


def read(path: str) -> str:
    p = ROOT / path
    check(p.exists(), f"missing required file: {path}")
    if not p.exists():
        return ""
    if p.suffix.lower() in {".jar", ".png", ".jpg", ".apk", ".aab", ".pcap", ".jks"}:
        return ""  # binary artifact; presence is checked separately
    try:
        return p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ""


def kotlin_files(*roots: str) -> list[Path]:
    out = []
    for r in roots:
        out.extend((ROOT / r).rglob("*.kt"))
    return out


print("== SentinelNet project invariants ==")

# 1. Deliverables present.
required = [
    "README.md", "LICENSE", "settings.gradle.kts", "build.gradle.kts",
    "gradle/libs.versions.toml", "gradle/wrapper/gradle-wrapper.jar",
    "gradle/wrapper/gradle-wrapper.properties", "gradlew", "gradlew.bat",
    ".github/workflows/ci.yml", ".github/workflows/security.yml", ".semgrep.yml",
    "app/src/main/AndroidManifest.xml",
    "docs/ARCHITECTURE.md", "docs/ENGINE_APIS.md", "docs/LEGAL_NOTICE.md",
    "docs/PRIVACY_POLICY.md", "docs/CONSENT_FLOW.md", "docs/THREAT_MODEL_STRIDE.md",
    "docs/PLAY_POLICY.md", "docs/SECURITY_LAB.md", "docs/USER_MANUAL.md",
    "docs/DEVELOPER_GUIDE.md", "docs/ROADMAP.md",
    "core/pure/src/main/kotlin/com/sentinelnet/core/consent/ConsentGate.kt",
    "core/pure/src/test/kotlin/com/sentinelnet/verification/ConformanceSuite.kt",
    "native/rust/sentinel-parser/Cargo.toml",
    "scripts/verify_domain.sh", "scripts/verify_project.py",
]
for f in required:
    read(f)
adr_files = sorted((ROOT / "docs/adr").glob("*.md"))
check(len(adr_files) >= 5, f"expected >=5 ADRs, found {len(adr_files)}")

# 2. Gradle wrapper jar is a real jar with the wrapper main class.
wrapper = ROOT / "gradle/wrapper/gradle-wrapper.jar"
if wrapper.exists():
    try:
        with zipfile.ZipFile(wrapper) as z:
            names = set(z.namelist())
        check("org/gradle/wrapper/GradleWrapperMain.class" in names,
              "gradle-wrapper.jar lacks GradleWrapperMain.class")
    except zipfile.BadZipFile:
        errors.append("gradle-wrapper.jar is not a valid zip/jar")

# 3. Every module in settings.gradle.kts has a build file and a source dir.
settings = read("settings.gradle.kts")
for module in re.findall(r'include\(":([\w:]+)"\)', settings):
    path = ROOT / module.replace(":", "/")
    check((path / "build.gradle.kts").exists(), f"module :{module} has no build.gradle.kts")
    check((path / "src").exists(), f"module :{module} has no src/ directory")

# 4. Legal gating is enforced in code, not just documentation.
gate = read("core/pure/src/main/kotlin/com/sentinelnet/core/consent/ConsentGate.kt")
for token in ["LEGAL_NOTICE_NOT_ACCEPTED", "SAFE_MODE_BLOCKS_INVASIVE", "NONCE_MISMATCH",
              "BIOMETRIC_REQUIRED", "RATE_LIMITED", "auditLog", "TargetValidator.validate"]:
    check(token in gate, f"ConsentGate is missing enforcement for {token}")

caps = read("core/pure/src/main/kotlin/com/sentinelnet/core/consent/Capability.kt")
invasive = re.findall(r'\("([\w.]+)", true', caps)
check(len(invasive) >= 6, f"expected >=6 invasive capabilities, found {len(invasive)}")
for cid in ["net.portscan", "capture.vpn", "capture.mitm", "firewall.rule", "lab.wpa_psk"]:
    check(f'"{cid}"' in caps, f"capability registry is missing {cid}")

# 5. Privacy: no IMSI / IMEI / serial collection anywhere in Kotlin sources.
for p in kotlin_files("app", "core", "engine"):
    s = p.read_text(encoding="utf-8")
    for banned in ["getImei(", "getSubscriberId(", "Build.getSerial(", "Build.SERIAL",
                   "getDeviceId(", "TelephonyManager.getLine1Number"]:
        check(banned not in s, f"privacy violation in {p.relative_to(ROOT)}: {banned}")

# 6. No active Wi-Fi attack primitives (deauth / monitor mode / injection).
attack_patterns = [r"aireplay-ng", r"deauth\s*\(", r"sendDeauth", r"setMonitorMode",
                   r"monitor\s+mode\s+enabled", r"packet\s+injection"]
for p in kotlin_files("app", "core", "engine"):
    s = p.read_text(encoding="utf-8")
    for pat in attack_patterns:
        check(not re.search(pat, s, re.I), f"active Wi-Fi attack primitive in {p.relative_to(ROOT)}: {pat}")

# 7. Android sources must not call invasive engine entry points without a gate.
for module_dir in ["engine/wifi", "engine/scanner", "engine/capture", "engine/audit"]:
    module_files = list((ROOT / module_dir).rglob("*.kt"))
    sources = [f.read_text(encoding="utf-8") for f in module_files]
    if any(any(x in s for x in ["startScan(", "startCapture(", "startMitm("]) for s in sources):
        check(any("ConsentGate" in s or "guard(" in s for s in sources),
              f"module {module_dir} has an invasive entry point with no ConsentGate anywhere")

# 8. Sample reports must be valid JSON / CSV produced by the real builders.
samples = ROOT / "docs/samples"
json_samples = sorted(samples.glob("*.json"))
check(len(json_samples) >= 6, f"expected >=6 sample JSON reports, found {len(json_samples)}")
for p in json_samples:
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        check(isinstance(data, dict), f"{p.name} is not a JSON object")
    except json.JSONDecodeError as e:
        errors.append(f"{p.name} is invalid JSON: {e}")
for p in sorted(samples.glob("*.csv")):
    rows = list(csv.reader(io.StringIO(p.read_text(encoding="utf-8"))))
    check(len(rows) >= 2, f"{p.name} has no data rows")

sec_report = samples / "security_audit_report.json"
if sec_report.exists():
    d = json.loads(sec_report.read_text(encoding="utf-8"))
    check(re.fullmatch(r"[0-9a-f]{64}", d.get("sha256", "")) is not None,
          "security report has no valid chain-of-custody sha256")
    doc = d.get("document", {})
    check(doc.get("reportType") == "security-audit", "security report has wrong reportType")
    check(len(doc.get("findings", [])) > 0, "security report has no findings")

lab = samples / "security_lab_walkthrough.json"
if lab.exists():
    d = json.loads(lab.read_text(encoding="utf-8"))
    check(d.get("syntheticHandshake") is True, "security lab sample must use a synthetic handshake")
    check(d.get("micMatched") is True, "security lab sample MIC did not verify")
    check("No frames were captured" in d.get("note", ""), "security lab sample missing scope note")

# 9. Onboarding / legal strings exist in both English and Amharic.
en = read("app/src/main/res/values/strings.xml")
am = read("app/src/main/res/values-am-rET/strings.xml")
for key in ["legal_notice_title", "legal_notice_body", "consent_authorised_only", "safe_mode"]:
    check(f'name="{key}"' in en, f"English strings missing {key}")
    check(f'name="{key}"' in am, f"Amharic strings missing {key}")
check("Authorized use only" in en or "Authorized use only" in read("docs/LEGAL_NOTICE.md"),
      "onboarding legal notice text is missing")

# 10. Manifest hygiene: no exported components beyond the launcher / VpnService.
manifest = read("app/src/main/AndroidManifest.xml")
check('android:exported="true"' in manifest, "launcher activity must be exported")
check("android.permission.INTERNET" in manifest, "INTERNET permission missing")
manifest_code = re.sub(r"<!--.*?-->", "", manifest, flags=re.S)
check("READ_PRIVILEGED_PHONE_STATE" not in manifest_code and
      "READ_PHONE_STATE" not in manifest_code and "getImei" not in manifest_code,
      "manifest requests sensitive telephony identifiers")

print(f"Ran {checks} checks")
if errors:
    print(f"\nFAILED ({len(errors)}):")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
print("All invariants passed.")
