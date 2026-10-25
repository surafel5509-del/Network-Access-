package com.sentinelnet.core.consent

/** How the user asserts the target is in scope. */
enum class AuthorizationScope {
    /** Device/network the user owns. */
    OWN_NETWORK,
    /** Written permission from the owner (e.g. a client engagement). */
    AUTHORIZED_ENGAGEMENT,
    /** Local lab / emulator / intentionally vulnerable test range. */
    LOCAL_LAB
}

/**
 * One consent dialog = one decision = one action. `nonce` ties the decision to a
 * specific request so a captured/old decision cannot be replayed to authorize a
 * different scan later. There is deliberately no "remember my choice".
 */
data class ConsentDecision(
    val capability: Capability,
    val nonce: String,
    val scope: AuthorizationScope,
    val target: String,
    val acknowledgedAuthorizedUse: Boolean,
    val acknowledgedLegalNoticeVersion: Int,
    val biometricVerified: Boolean = false,
    val publicTargetAcknowledged: Boolean = false,
    val justification: String = "",
    val grantedAtMillis: Long
) {
    fun isExpired(nowMillis: Long, ttlMillis: Long): Boolean =
        nowMillis - grantedAtMillis > ttlMillis || nowMillis < grantedAtMillis

    /** Whether the user confirmed the four mandatory statements in the dialog. */
    val isWellFormed: Boolean
        get() = acknowledgedLegalNoticeVersion >= ConsentPolicy.CURRENT_NOTICE_VERSION &&
            target.isNotBlank() && nonce.length >= 8
}

data class ConsentRequest(
    val capability: Capability,
    val nonce: String,
    val target: String,
    val actor: String,
    val sessionId: String,
    val decision: ConsentDecision? = null
)

sealed interface ConsentResult<out T> {
    data class Allowed<T>(val value: T) : ConsentResult<T>
    data class Denied(val reason: DenialReason, val detail: String) : ConsentResult<Nothing>

    val isAllowed: Boolean get() = this is Allowed
    fun getOrNull(): T? = (this as? Allowed)?.value
}

enum class DenialReason {
    LEGAL_NOTICE_NOT_ACCEPTED,
    STALE_LEGAL_NOTICE,
    SAFE_MODE_BLOCKS_INVASIVE,
    NO_DECISION,
    MALFORMED_DECISION,
    NONCE_MISMATCH,
    NONCE_ALREADY_USED,
    CAPABILITY_MISMATCH,
    TARGET_MISMATCH,
    CONSENT_EXPIRED,
    BIOMETRIC_REQUIRED,
    TARGET_OUT_OF_SCOPE,
    PUBLIC_TARGET_NOT_ACKNOWLEDGED,
    RATE_LIMITED,
    ACTION_FAILED
}

/** The policy is persisted (DataStore) and injected; the in-memory default is fail-closed. */
data class ConsentPolicy(
    val legalNoticeAccepted: Boolean = false,
    val acceptedNoticeVersion: Int = 0,
    val safeMode: Boolean = true,
    val maxInvasiveActionsPerMinute: Int = 12
) {
    companion object {
        /** Bump on every material change to docs/LEGAL_NOTICE.md; forces re-consent. */
        const val CURRENT_NOTICE_VERSION: Int = 1
        const val CONSENT_TTL_MILLIS: Long = 10 * 60 * 1000L
    }
}

fun interface Clock { fun nowMillis(): Long }

object SystemClock : Clock { override fun nowMillis(): Long = System.currentTimeMillis() }
