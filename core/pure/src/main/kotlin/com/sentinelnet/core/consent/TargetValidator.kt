package com.sentinelnet.core.consent

import com.sentinelnet.core.domain.NetworkMath

enum class TargetClass { LOCAL_PRIVATE, LOCAL_LAB, PUBLIC, INVALID }

data class TargetVerdict(val allowed: Boolean, val targetClass: TargetClass, val reason: String)

/**
 * Scope enforcement. Passive observers (Wi-Fi scan) never call this. Every
 * active action is checked: by default SentinelNet only sends probes at
 * RFC1918/lab addresses. Public targets require a second, explicit
 * acknowledgement plus a written justification, and are always logged.
 */
object TargetValidator {
    fun validate(
        target: String,
        scope: AuthorizationScope,
        publicTargetAcknowledged: Boolean,
        justification: String
    ): TargetVerdict {
        val cleaned = target.trim().substringBefore('/')
        if (cleaned.isBlank()) return TargetVerdict(false, TargetClass.INVALID, "Empty target")
        if (NetworkMath.isMulticastOrBroadcast(cleaned)) {
            return TargetVerdict(false, TargetClass.INVALID, "Broadcast/multicast targets are never probed")
        }
        if (!NetworkMath.isValidIp(cleaned) && !isPlainHostname(cleaned)) {
            return TargetVerdict(false, TargetClass.INVALID, "Target is not a valid IP or hostname")
        }
        if (NetworkMath.isPrivateOrLab(cleaned)) {
            val cls = if (scope == AuthorizationScope.LOCAL_LAB) TargetClass.LOCAL_LAB else TargetClass.LOCAL_PRIVATE
            return TargetVerdict(true, cls, "Local/authorized address")
        }
        if (!publicTargetAcknowledged) {
            return TargetVerdict(false, TargetClass.PUBLIC, "Public target needs explicit acknowledgement")
        }
        if (justification.isBlank() || justification.length < 8) {
            return TargetVerdict(false, TargetClass.PUBLIC, "Written authorization justification is required")
        }
        if (scope == AuthorizationScope.LOCAL_LAB) {
            return TargetVerdict(false, TargetClass.PUBLIC, "A public address cannot be declared a local lab")
        }
        return TargetVerdict(
            true, TargetClass.PUBLIC,
            "Public target allowed by explicit acknowledgement + justification (logged)"
        )
    }

    private fun isPlainHostname(value: String): Boolean {
        if (value.length > 253 || value.startsWith('-') || value.endsWith('-')) return false
        val labelRegex = Regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
        return value.split('.').all { it.isNotBlank() && labelRegex.matches(it) }
    }
}
