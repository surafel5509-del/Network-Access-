package com.sentinelnet.core.consent

import com.sentinelnet.core.model.AuditEvent

/**
 * THE enforcement point for legal/ethical gating.
 *
 * No engine may perform an invasive action without going through `guard()`.
 * The gate:
 *  1. requires an accepted, current legal notice;
 *  2. respects Safe Mode for every invasive capability;
 *  3. requires a fresh, well-formed, single-use consent decision bound to a nonce;
 *  4. verifies biometric confirmation where configured;
 *  5. validates target scope (private/lab by default, public only with extra ack);
 *  6. applies a sliding-window rate limit;
 *  7. writes an audit event for BOTH allowed and denied attempts, before the action.
 *
 * Design note: the return type is a sealed result rather than an exception, so
 * callers cannot accidentally forget to handle a denial. There is deliberately
 * no bypass flag and no "trust me" overload.
 */
class ConsentGate(
    private var policy: ConsentPolicy = ConsentPolicy(),
    private val auditLog: AuditLog = InMemoryAuditLog(),
    private val clock: Clock = SystemClock,
    private val rateLimiter: RateLimiter = RateLimiter(clock)
) {
    fun currentPolicy(): ConsentPolicy = policy

    fun updatePolicy(newPolicy: ConsentPolicy) { policy = newPolicy }

    fun auditTrail(): List<AuditEvent> = auditLog.all()

    // Single-use nonces: even a valid decision cannot authorize two actions.
    private val usedNonces = HashSet<String>()
    private val nonceLock = Any()

    private fun markNonceUsed(nonce: String): Boolean = synchronized(nonceLock) { usedNonces.add(nonce) }

    fun <T> guard(request: ConsentRequest, action: () -> T): ConsentResult<T> {
        val cap = request.capability
        val now = clock.nowMillis()
        val d = request.decision

        fun deny(reason: DenialReason, detail: String): ConsentResult<T> {
            log(request, "DENIED", "$reason: $detail")
            return ConsentResult.Denied(reason, detail)
        }

        // 1. Legal notice — global, versioned, fail-closed.
        if (!policy.legalNoticeAccepted) {
            return deny(DenialReason.LEGAL_NOTICE_NOT_ACCEPTED, "Onboarding legal notice not accepted")
        }
        if (policy.acceptedNoticeVersion < ConsentPolicy.CURRENT_NOTICE_VERSION) {
            return deny(DenialReason.STALE_LEGAL_NOTICE, "Legal notice was updated; re-consent required")
        }
        // 2. Safe Mode.
        if (cap.invasive && policy.safeMode) {
            return deny(DenialReason.SAFE_MODE_BLOCKS_INVASIVE, "Safe Mode disables ${cap.id}")
        }
        // 3. Consent decision.
        if (d == null) return deny(DenialReason.NO_DECISION, "No consent decision attached to request")
        if (!d.isWellFormed || !d.acknowledgedAuthorizedUse) {
            return deny(DenialReason.MALFORMED_DECISION, "Consent dialog was not fully acknowledged")
        }
        if (d.capability != cap) {
            return deny(DenialReason.CAPABILITY_MISMATCH, "Decision was for ${d.capability.id}, need ${cap.id}")
        }
        if (d.nonce != request.nonce) {
            return deny(DenialReason.NONCE_MISMATCH, "Decision does not match this request (replay?)")
        }
        if (d.target.trim() != request.target.trim()) {
            return deny(DenialReason.TARGET_MISMATCH, "Decision target does not match requested target")
        }
        if (d.isExpired(now, ConsentPolicy.CONSENT_TTL_MILLIS)) {
            return deny(DenialReason.CONSENT_EXPIRED, "Consent older than 10 minutes")
        }
        // 4. Biometric.
        if (cap.requiresBiometric && !d.biometricVerified) {
            return deny(DenialReason.BIOMETRIC_REQUIRED, "${cap.id} requires a fresh biometric prompt")
        }
        // 5. Target scope — only active capabilities need a target.
        if (cap.invasive) {
            val verdict = TargetValidator.validate(
                target = request.target,
                scope = d.scope,
                publicTargetAcknowledged = d.publicTargetAcknowledged,
                justification = d.justification
            )
            if (!verdict.allowed) {
                val reason = if (verdict.targetClass == TargetClass.PUBLIC) {
                    DenialReason.PUBLIC_TARGET_NOT_ACKNOWLEDGED
                } else {
                    DenialReason.TARGET_OUT_OF_SCOPE
                }
                return deny(reason, verdict.reason)
            }
            // 6. Rate limit (only invasive actions consume budget).
            if (!rateLimiter.tryAcquire(cap.id, policy.maxInvasiveActionsPerMinute)) {
                return deny(DenialReason.RATE_LIMITED, "Too many ${cap.id} actions in the last minute")
            }
        }
        // 7. Single-use: consume the nonce. A second action with the same
        //    decision must be rejected even if it arrives within the TTL.
        if (cap.invasive && !markNonceUsed(request.nonce)) {
            return deny(DenialReason.NONCE_ALREADY_USED, "This consent decision was already used")
        }
        // 8. ALLOW — write the audit record BEFORE running the action.
        log(request, "ALLOWED", "${d.scope} / ${TargetValidator.validate(
            request.target, d.scope, d.publicTargetAcknowledged, d.justification
        ).targetClass}")
        return try {
            ConsentResult.Allowed(action())
        } catch (t: Throwable) {
            // Even a crash is auditable; never leak the exception to the UI unchecked.
            log(request, "ERROR", t.javaClass.simpleName ?: "Throwable")
            ConsentResult.Denied(DenialReason.ACTION_FAILED, t.javaClass.simpleName ?: "action failed")
        }
    }

    /** Passive capabilities (e.g. Wi-Fi scan) still get an audit record but no dialog. */
    fun <T> observe(request: ConsentRequest, action: () -> T): ConsentResult<T> {
        if (!policy.legalNoticeAccepted) {
            log(request, "DENIED", "LEGAL_NOTICE_NOT_ACCEPTED")
            return ConsentResult.Denied(DenialReason.LEGAL_NOTICE_NOT_ACCEPTED, "Legal notice not accepted")
        }
        if (request.capability.invasive) {
            log(request, "DENIED", "SAFE_MODE_BLOCKS_INVASIVE: observe() cannot be used for ${request.capability.id}")
            return ConsentResult.Denied(
                DenialReason.SAFE_MODE_BLOCKS_INVASIVE,
                "Invasive capability ${request.capability.id} must use guard()"
            )
        }
        log(request, "OBSERVED", "passive")
        return try {
            ConsentResult.Allowed(action())
        } catch (t: Throwable) {
            ConsentResult.Denied(DenialReason.ACTION_FAILED, t.javaClass.simpleName ?: "action failed")
        }
    }

    private fun log(request: ConsentRequest, decision: String, reason: String) {
        (auditLog as? InMemoryAuditLog)?.record(
            clock = clock,
            actor = request.actor,
            capability = request.capability.id,
            target = request.target,
            decision = decision,
            reason = reason,
            sessionId = request.sessionId
        ) ?: auditLog.append(
            AuditEvent(
                sequence = auditLog.size() + 1L,
                timestampMillis = clock.nowMillis(),
                actor = request.actor,
                capability = request.capability.id,
                target = request.target,
                decision = decision,
                reason = reason,
                sessionId = request.sessionId
            )
        )
    }
}
