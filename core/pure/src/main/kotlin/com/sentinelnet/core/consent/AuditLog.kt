package com.sentinelnet.core.consent

import com.sentinelnet.core.model.AuditEvent

/**
 * Append-only audit trail. The Android implementation is backed by a SQLCipher
 * Room table and is written BEFORE the guarded action starts.
 *
 * Privacy rule: never store IMSI, IMEI, serial, advertising ID, or raw packet
 * payloads here. `target` is an IP/hostname only, and `actor` is a local
 * pseudonymous session identifier, never a person's name.
 */
interface AuditLog {
    fun append(event: AuditEvent)
    fun all(): List<AuditEvent>
    fun forSession(sessionId: String): List<AuditEvent> = all().filter { it.sessionId == sessionId }
    fun size(): Int = all().size
    fun clear()
}

/** Thread-safe reference implementation used by unit tests and the domain conformance suite. */
class InMemoryAuditLog : AuditLog {
    private val lock = Any()
    private val events = mutableListOf<AuditEvent>()
    private var sequence = 0L

    override fun append(event: AuditEvent) {
        synchronized(lock) { events += event }
    }

    /** Builds the event with a monotonic sequence, so ordering is stable across exports. */
    fun record(
        clock: Clock,
        actor: String,
        capability: String,
        target: String,
        decision: String,
        reason: String,
        sessionId: String
    ): AuditEvent {
        val event = synchronized(lock) {
            sequence += 1
            AuditEvent(
                sequence = sequence,
                timestampMillis = clock.nowMillis(),
                actor = actor,
                capability = capability,
                target = target,
                decision = decision,
                reason = reason,
                sessionId = sessionId
            ).also { events += it }
        }
        return event
    }

    override fun all(): List<AuditEvent> = synchronized(lock) { events.toList() }
    override fun clear() = synchronized(lock) { events.clear(); sequence = 0L }
}
