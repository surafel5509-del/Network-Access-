package com.sentinelnet.core.domain

import com.sentinelnet.core.model.CveHint
import com.sentinelnet.core.model.Finding
import com.sentinelnet.core.model.ScoreCategory
import com.sentinelnet.core.model.Severity

/**
 * PASSIVE vulnerability hinting. This is a *sample* local database used for
 * offline operation; the shipped product refreshes it from NVD/CISA KEV with
 * user opt-in (Module D5). Nothing here probes, exploits or verifies a CVE —
 * a version-string match is only a hint, and the UI must say so.
 */
class CveHintMatcher(private val hints: List<CveHint> = DEFAULT_HINTS) {

    fun match(service: String?, version: String?, banner: String?, target: String, nowMillis: Long = 0L): List<Finding> {
        val haystack = listOfNotNull(service, version, banner).joinToString(" ").lowercase()
        if (haystack.isBlank()) return emptyList()
        return hints.filter { hint ->
            haystack.contains(hint.servicePattern.lowercase()) && versionMatches(haystack, hint.versionPattern)
        }.map { hint ->
            Finding(
                id = "cvehint.$target.${hint.cveId}",
                title = "Possible ${hint.cveId} affecting ${hint.servicePattern}",
                detail = "Version string suggests ${hint.servicePattern} ${hint.versionPattern}. " +
                    "${hint.summary} This is a passive hint, NOT a confirmed vulnerability; verify with the vendor.",
                severity = hint.severity,
                category = ScoreCategory.NETWORK,
                remediation = "Confirm the installed version and apply the vendor patch if applicable.",
                evidence = mapOf("banner" to (banner ?: ""), "version" to (version ?: "")),
                referenceUrl = hint.nvdUrl,
                detectedAtMillis = nowMillis
            )
        }
    }

    private fun versionMatches(haystack: String, pattern: String): Boolean {
        if (pattern.isBlank() || pattern == "*") return true
        return pattern.lowercase().split('|').any { haystack.contains(it.trim()) }
    }

    companion object {
        val DEFAULT_HINTS = listOf(
            CveHint("CVE-2023-38408", "openssh", "7.4|8.9|9.2", "OpenSSH forwarded ssh-agent remote code execution (verify exact version).", Severity.HIGH),
            CveHint("CVE-2021-44228", "log4j", "2.0|2.14", "Log4Shell JNDI lookup RCE in Log4j 2.x.", Severity.CRITICAL),
            CveHint("CVE-2019-0708", "rdp", "5.1|5.2|6.0|6.1|7.0|8.0|8.1", "BlueKeep: unauthenticated RDP wormable flaw on legacy Windows.", Severity.CRITICAL),
            CveHint("CVE-2017-0144", "smb", "1.0|v1", "EternalBlue / SMBv1 remote code execution.", Severity.CRITICAL),
            CveHint("CVE-2014-0160", "openssl", "1.0.1", "Heartbleed: TLS heartbeat memory disclosure.", Severity.HIGH),
            CveHint("CVE-2021-41773", "apache", "2.4.49|2.4.50", "Apache HTTP Server path traversal and possible RCE.", Severity.HIGH),
            CveHint("CVE-2018-15473", "openssh", "7.7|2.3", "OpenSSH username enumeration via malformed auth packets.", Severity.MEDIUM),
            CveHint("CVE-2022-1388", "f5", "big-ip", "F5 BIG-IP iControl REST authentication bypass.", Severity.CRITICAL)
        )
    }
}
