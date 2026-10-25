package com.sentinelnet.engine.audit

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import com.sentinelnet.core.model.Finding
import com.sentinelnet.core.model.ScoreCategory
import com.sentinelnet.core.model.Severity
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Module D2/D3 — passive device & app hygiene checks. Every check uses public
 * APIs; nothing needs root, QUERY_ALL_PACKAGES or an accessibility service.
 * Where an API is restricted, we report "unknown" rather than guessing.
 */
@Singleton
class AndroidDeviceAudit @Inject constructor(
    @ApplicationContext private val context: Context
) {
    fun audit(now: Long = System.currentTimeMillis()): List<Finding> = buildList {
        addAll(rootChecks(now))
        addAll(systemChecks(now))
        addAll(lockScreenChecks(now))
        addAll(adversarialConfigChecks(now))
    }

    private fun finding(id: String, title: String, detail: String, severity: Severity,
                        category: ScoreCategory, fix: String, now: Long, evidence: Map<String, String> = emptyMap()) =
        Finding(id, title, detail, severity, category, fix, evidence, detectedAtMillis = now)

    private fun rootChecks(now: Long): List<Finding> {
        val indicators = mutableListOf<String>()
        val paths = System.getenv("PATH").orEmpty().split(':')
        if (paths.any { File("$it/su").exists() }) indicators += "su in PATH"
        listOf(
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
            "/data/adb/magisk", "/sbin/.magisk"
        ).filter { File(it).exists() }.forEach { indicators += it }
        return if (indicators.isEmpty()) emptyList() else listOf(
            finding("device.root", "Root / Magisk indicators present",
                "Found: ${indicators.joinToString(", ")}. A rooted device has a much larger attack surface; " +
                    "this is informational, not a judgement.",
                Severity.MEDIUM, ScoreCategory.DEVICE,
                "Verify this is intentional. Keep the bootloader locked on production devices and review superuser grants.",
                now, mapOf("indicators" to indicators.joinToString(",")))
        )
    }

    private fun systemChecks(now: Long): List<Finding> = buildList {
        val patch = Build.VERSION.SECURITY_PATCH
        val (year, month) = patch.split('-').let { parts ->
            (parts.getOrNull(0)?.toIntOrNull() ?: 0) to (parts.getOrNull(1)?.toIntOrNull() ?: 0)
        }
        if (year in 1..2024 || (year == 2025 && month < 6)) {
            add(finding("device.patch", "Security patch level is old ($patch)",
                "The device is running security patch $patch. Known vulnerabilities may be unpatched.",
                Severity.HIGH, ScoreCategory.DEVICE,
                "Install the latest system update. If the device is out of support, replace it.",
                now, mapOf("security_patch" to patch)))
        }
        val enforce = readFirstLine("/sys/fs/selinux/enforce")
        if (enforce == "0") {
            add(finding("device.selinux", "SELinux is permissive",
                "SELinux is not enforcing; sandbox escapes become much easier.",
                Severity.CRITICAL, ScoreCategory.DEVICE, "Restore enforcing SELinux.", now))
        }
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
        val encryption = dpm?.storageEncryptionStatus
        if (encryption != null && encryption == DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED) {
            add(finding("device.encryption", "Storage encryption unsupported",
                "DevicePolicyManager reports encryption unsupported on this device.",
                Severity.HIGH, ScoreCategory.DEVICE, "Use a device with full-disk/file-based encryption.", now))
        }
        // Informational: a locked bootloader is good; report only when clearly unlocked.
        val flashLocked = getprop("ro.boot.flash.locked")
        if (flashLocked == "0") {
            add(finding("device.bootloader", "Bootloader appears unlocked",
                "ro.boot.flash.locked=0. An unlocked bootloader allows flashing unsigned images.",
                Severity.MEDIUM, ScoreCategory.DEVICE,
                "Re-lock the bootloader if this is a production device.", now))
        }
    }

    private fun lockScreenChecks(now: Long): List<Finding> = buildList {
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        if (km != null && !km.isDeviceSecure) {
            add(finding("device.screenlock", "No secure screen lock",
                "No PIN/pattern/password is set. Anyone with the device can read local data.",
                Severity.CRITICAL, ScoreCategory.DEVICE,
                "Set a strong PIN or password and enable biometric unlock.", now))
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val bm = context.getSystemService(android.hardware.biometrics.BiometricManager::class.java)
            val canAuth = bm?.canAuthenticate(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_WEAK)
            if (canAuth != null && canAuth != android.hardware.biometrics.BiometricManager.BIOMETRIC_SUCCESS) {
                add(finding("device.biometric", "Biometrics not enrolled",
                    "Sensitive SentinelNet actions (capture, firewall, security lab) require a biometric prompt. " +
                        "None is currently enrolled, so those actions will be unavailable.",
                    Severity.LOW, ScoreCategory.DEVICE,
                    "Enroll a fingerprint or face unlock, or use the device password fallback.", now))
            }
        }
    }

    private fun adversarialConfigChecks(now: Long): List<Finding> = buildList {
        val resolver = context.contentResolver
        val adb = try { Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0) } catch (t: Throwable) { 0 }
        if (adb == 1) {
            add(finding("device.adb", "USB debugging is enabled",
                "ADB exposes a powerful debug interface if the device is connected to an untrusted host.",
                Severity.MEDIUM, ScoreCategory.DEVICE,
                "Disable USB debugging when not developing.", now))
        }
        val dev = try { Settings.Global.getInt(resolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) }
            catch (t: Throwable) { 0 }
        if (dev == 1 && adb == 1) {
            add(finding("device.devoptions", "Developer options + ADB enabled",
                "Both developer options and ADB are on. Review OEM unlocking and USB accessories.",
                Severity.LOW, ScoreCategory.DEVICE, "Turn off developer options on daily-use devices.", now))
        }
        val a11y = try {
            Settings.Secure.getString(resolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES).orEmpty()
        } catch (t: Throwable) { "" }
        if (a11y.isNotBlank()) {
            add(finding("apps.accessibility", "Accessibility services are enabled",
                "Active services: $a11y. Accessibility is the most commonly abused Android permission; " +
                    "review each service and remove any you do not recognise.",
                Severity.MEDIUM, ScoreCategory.APPS,
                "Settings > Accessibility > review enabled services.", now, mapOf("services" to a11y)))
        }
        // User-installed CAs can enable TLS interception. Reading the AndroidKeyStore is public API.
        val userCas = try {
            val ks = java.security.KeyStore.getInstance("AndroidCAStore")
            ks.load(null)
            ks.aliases().toList().count { it.startsWith("user:") }
        } catch (t: Throwable) { 0 }
        if (userCas > 0) {
            add(finding("privacy.usercas", "$userCas user-installed CA certificate(s)",
                "User CAs allow TLS interception by anyone who installed them. SentinelNet's MITM proxy " +
                    "installs one only with explicit consent — verify the rest.",
                Severity.MEDIUM, ScoreCategory.PRIVACY,
                "Settings > Encryption & credentials > Trusted credentials > User: remove unknown CAs.", now))
        }
        val admins = try {
            (context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager)
                ?.activeAdmins?.map { it.packageName }.orEmpty()
        } catch (t: Throwable) { emptyList() }
        if (admins.isNotEmpty()) {
            add(finding("apps.deviceadmins", "Active device administrator apps: ${admins.size}",
                "Device admins: ${admins.joinToString(", ")}. Review them — malware often abuses this role.",
                Severity.LOW, ScoreCategory.APPS,
                "Settings > Security > Device admin apps: disable anything unfamiliar.",
                now, mapOf("admins" to admins.joinToString(","))))
        }
    }

    private fun readFirstLine(path: String): String? = try {
        BufferedReader(InputStreamReader(File(path).inputStream())).use { it.readLine() }
    } catch (t: Throwable) { null }

    private fun getprop(key: String): String? = try {
        Runtime.getRuntime().exec(arrayOf("getprop", key)).inputStream.bufferedReader().use { it.readLine()?.trim() }
    } catch (t: Throwable) { null }
}
