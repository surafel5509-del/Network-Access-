package com.sentinelnet.app

import com.sentinelnet.core.consent.AuthorizationScope
import com.sentinelnet.core.consent.Capability
import com.sentinelnet.core.consent.Clock
import com.sentinelnet.core.consent.ConsentDecision
import com.sentinelnet.core.consent.ConsentGate
import com.sentinelnet.core.consent.ConsentPolicy
import com.sentinelnet.core.consent.ConsentRequest
import com.sentinelnet.core.consent.ConsentResult
import com.sentinelnet.core.consent.DenialReason
import com.sentinelnet.core.consent.InMemoryAuditLog
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Verifies the UI-facing gate contract from the app module's perspective. */
class ConsentGateIntegrationTest {
    private class FixedClock(var now: Long = 1_000L) : Clock {
        override fun nowMillis(): Long = now
    }

    private fun decision(nonce: String) = ConsentDecision(
        capability = Capability.PORT_SCAN, nonce = nonce,
        scope = AuthorizationScope.OWN_NETWORK, target = "192.168.1.1",
        acknowledgedAuthorizedUse = true,
        acknowledgedLegalNoticeVersion = ConsentPolicy.CURRENT_NOTICE_VERSION,
        biometricVerified = false, grantedAtMillis = 1_000L
    )

    @Test fun `safe mode blocks a scan even with a valid decision`() {
        val log = InMemoryAuditLog()
        val gate = ConsentGate(
            ConsentPolicy(true, ConsentPolicy.CURRENT_NOTICE_VERSION, true),
            log, FixedClock()
        )
        val result = gate.guard(
            ConsentRequest(Capability.PORT_SCAN, "n-12345678", "192.168.1.1", "u", "s", decision("n-12345678"))
        ) { "ran" }
        assertTrue(result is ConsentResult.Denied)
        assertEquals(DenialReason.SAFE_MODE_BLOCKS_INVASIVE, (result as ConsentResult.Denied).reason)
        assertEquals("DENIED", log.all().single().decision)
    }

    @Test fun `a valid decision allows exactly one scan`() {
        val gate = ConsentGate(
            ConsentPolicy(true, ConsentPolicy.CURRENT_NOTICE_VERSION, false),
            InMemoryAuditLog(), FixedClock()
        )
        fun request() = ConsentRequest(Capability.PORT_SCAN, "n-87654321", "192.168.1.1", "u", "s", decision("n-87654321"))
        assertEquals("ran", (gate.guard(request()) { "ran" } as ConsentResult.Allowed).value)
        val replay = gate.guard(request()) { "again" }
        assertEquals(DenialReason.NONCE_ALREADY_USED, (replay as ConsentResult.Denied).reason)
    }
}
