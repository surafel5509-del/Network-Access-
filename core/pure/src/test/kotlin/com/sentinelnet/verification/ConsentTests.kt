package com.sentinelnet.verification

import com.sentinelnet.core.consent.AuthorizationScope
import com.sentinelnet.core.consent.Capability
import com.sentinelnet.core.consent.Clock
import com.sentinelnet.core.consent.ConsentDecision
import com.sentinelnet.core.consent.ConsentGate
import com.sentinelnet.core.consent.ConsentPolicy
import com.sentinelnet.core.consent.ConsentRequest
import com.sentinelnet.core.consent.DenialReason
import com.sentinelnet.core.consent.InMemoryAuditLog
import com.sentinelnet.core.consent.RateLimiter
import com.sentinelnet.core.consent.TargetValidator
import com.sentinelnet.core.domain.NetworkMath

class MutableClock(var now: Long = 1_000L) : Clock {
    override fun nowMillis(): Long = now
}

private fun dec(
    cap: Capability = Capability.PORT_SCAN,
    nonce: String = "nonce-12345678",
    target: String = "192.168.1.1",
    now: Long = 1_000L,
    authorized: Boolean = true,
    bio: Boolean = false,
    publicAck: Boolean = false,
    justification: String = ""
) = ConsentDecision(
    capability = cap, nonce = nonce, scope = AuthorizationScope.OWN_NETWORK, target = target,
    acknowledgedAuthorizedUse = authorized,
    acknowledgedLegalNoticeVersion = ConsentPolicy.CURRENT_NOTICE_VERSION,
    biometricVerified = bio, publicTargetAcknowledged = publicAck,
    justification = justification, grantedAtMillis = now
)

private fun req(
    cap: Capability = Capability.PORT_SCAN,
    nonce: String = "nonce-12345678",
    target: String = "192.168.1.1",
    d: ConsentDecision? = dec(cap, nonce, target)
) = ConsentRequest(cap, nonce, target, "local-session-1", "sess-1", d)

private fun cleanGate(
    log: InMemoryAuditLog = InMemoryAuditLog(),
    clock: MutableClock = MutableClock(),
    maxPerMinute: Int = 100
): Triple<ConsentGate, InMemoryAuditLog, MutableClock> {
    val gate = ConsentGate(
        policy = ConsentPolicy(
            legalNoticeAccepted = true,
            acceptedNoticeVersion = ConsentPolicy.CURRENT_NOTICE_VERSION,
            safeMode = false,
            maxInvasiveActionsPerMinute = maxPerMinute
        ),
        auditLog = log, clock = clock, rateLimiter = RateLimiter(clock)
    )
    return Triple(gate, log, clock)
}

fun consentTests() = Harness.section("consent-gate") {
    Harness.test("fail-closed: legal notice not accepted") {
        val log = InMemoryAuditLog()
        val gate = ConsentGate(auditLog = log, clock = MutableClock())
        val r = gate.guard(req()) { "should-not-run" }
        Harness.assertEquals(DenialReason.LEGAL_NOTICE_NOT_ACCEPTED, (r as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
        Harness.assertEquals(1, log.size())
        Harness.assertEquals("DENIED", log.all().single().decision)
    }

    Harness.test("stale legal notice version forces re-consent") {
        val (gate, _, _) = cleanGate()
        gate.updatePolicy(gate.currentPolicy().copy(acceptedNoticeVersion = 0))
        val r = gate.guard(req()) { 1 }
        Harness.assertEquals(DenialReason.STALE_LEGAL_NOTICE, (r as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
    }

    Harness.test("Safe Mode blocks every invasive capability") {
        for (cap in Capability.entries.filter { it.invasive }) {
            val log = InMemoryAuditLog()
            val gate = ConsentGate(
                policy = ConsentPolicy(true, ConsentPolicy.CURRENT_NOTICE_VERSION, safeMode = true),
                auditLog = log
            )
            val r = gate.guard(req(cap = cap, d = dec(cap = cap, bio = true))) { 1 }
            Harness.assertEquals(DenialReason.SAFE_MODE_BLOCKS_INVASIVE,
                (r as com.sentinelnet.core.consent.ConsentResult.Denied).reason, cap.id)
        }
    }

    Harness.test("missing decision is denied") {
        val (gate, _, _) = cleanGate()
        Harness.assertEquals(DenialReason.NO_DECISION,
            (gate.guard(req(d = null)) { 1 } as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
    }

    Harness.test("unacknowledged consent is malformed") {
        val (gate, _, _) = cleanGate()
        Harness.assertEquals(DenialReason.MALFORMED_DECISION,
            (gate.guard(req(d = dec(authorized = false))) { 1 } as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
    }

    Harness.test("nonce mismatch blocks replayed consent") {
        val (gate, _, _) = cleanGate()
        Harness.assertEquals(DenialReason.NONCE_MISMATCH,
            (gate.guard(req(nonce = "other-nonce-999", d = dec())) { 1 } as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
    }

    Harness.test("capability mismatch") {
        val (gate, _, _) = cleanGate()
        Harness.assertEquals(DenialReason.CAPABILITY_MISMATCH,
            (gate.guard(req(cap = Capability.PORT_SCAN, d = dec(cap = Capability.PACKET_CAPTURE))) { 1 }
                as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
    }

    Harness.test("target mismatch") {
        val (gate, _, _) = cleanGate()
        Harness.assertEquals(DenialReason.TARGET_MISMATCH,
            (gate.guard(req(target = "192.168.1.2", d = dec())) { 1 }
                as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
    }

    Harness.test("expired consent (>10 min)") {
        val clock = MutableClock(1_000L + ConsentPolicy.CONSENT_TTL_MILLIS + 1)
        val log = InMemoryAuditLog()
        val gate = ConsentGate(
            ConsentPolicy(true, ConsentPolicy.CURRENT_NOTICE_VERSION, false, 100), log, clock, RateLimiter(clock))
        Harness.assertEquals(DenialReason.CONSENT_EXPIRED,
            (gate.guard(req()) { 1 } as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
    }

    Harness.test("biometric required for capture + firewall + lab") {
        val (gate, _, _) = cleanGate()
        val cap = Capability.PACKET_CAPTURE
        val noBio = dec(cap = cap, bio = false)
        Harness.assertEquals(DenialReason.BIOMETRIC_REQUIRED,
            (gate.guard(req(cap = cap, d = noBio)) { 1 } as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
        val withBio = dec(cap = cap, bio = true)
        Harness.assertTrue(gate.guard(req(cap = cap, d = withBio)) { 42 }.isAllowed)
    }

    Harness.test("public target requires additional acknowledgement + justification") {
        val (gate, _, _) = cleanGate()
        val r1 = gate.guard(req(target = "8.8.8.8", d = dec(target = "8.8.8.8"))) { 1 }
        Harness.assertEquals(DenialReason.PUBLIC_TARGET_NOT_ACKNOWLEDGED,
            (r1 as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
        val r2 = gate.guard(req(target = "8.8.8.8", d = dec(target = "8.8.8.8", publicAck = true, justification = ""))) { 1 }
        Harness.assertEquals(DenialReason.PUBLIC_TARGET_NOT_ACKNOWLEDGED,
            (r2 as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
        val r3 = gate.guard(req(target = "8.8.8.8", d = dec(target = "8.8.8.8", publicAck = true,
            justification = "Written authorization for client engagement #42"))) { "ok" }
        Harness.assertEquals("ok", r3.getOrNull())
    }

    Harness.test("rate limit stops a scan burst") {
        val (gate, _, clock) = cleanGate(maxPerMinute = 2)
        Harness.assertTrue(gate.guard(req(nonce = "nonce-a-1234", d = dec(nonce = "nonce-a-1234"))) { 1 }.isAllowed)
        Harness.assertTrue(gate.guard(req(nonce = "nonce-b-1234", d = dec(nonce = "nonce-b-1234"))) { 2 }.isAllowed)
        val third = gate.guard(req(nonce = "nonce-c-1234", d = dec(nonce = "nonce-c-1234"))) { 3 }
        Harness.assertEquals(DenialReason.RATE_LIMITED, (third as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
        clock.now += 61_000L
        Harness.assertTrue(gate.guard(req(nonce = "nonce-d-1234", d = dec(nonce = "nonce-d-1234", now = clock.now))) { 4 }.isAllowed)
    }

    Harness.test("an allowed decision cannot be replayed (single-use nonce)") {
        val (gate, _, _) = cleanGate()
        val first = gate.guard(req(nonce = "single-use-1234", d = dec(nonce = "single-use-1234"))) { 1 }
        Harness.assertTrue(first.isAllowed)
        val replay = gate.guard(req(nonce = "single-use-1234", d = dec(nonce = "single-use-1234"))) { 2 }
        Harness.assertEquals(DenialReason.NONCE_ALREADY_USED,
            (replay as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
    }

    Harness.test("observe() cannot be used for invasive capabilities") {
        val (gate, _, _) = cleanGate()
        Harness.assertEquals(DenialReason.SAFE_MODE_BLOCKS_INVASIVE,
            (gate.observe(req(cap = Capability.PORT_SCAN)) { 1 } as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
    }

    Harness.test("passive observation works and is audited") {
        val (gate, log, _) = cleanGate()
        val r = gate.observe(req(cap = Capability.WIFI_SCAN, d = null)) { 7 }
        Harness.assertEquals(7, r.getOrNull())
        Harness.assertEquals("OBSERVED", log.all().last().decision)
    }

    Harness.test("allowed action runs once and audit record precedes it") {
        val (gate, log, _) = cleanGate()
        var calls = 0
        val r = gate.guard(req()) { calls++; "done" }
        Harness.assertEquals("done", r.getOrNull())
        Harness.assertEquals(1, calls)
        Harness.assertEquals("ALLOWED", log.all().last().decision)
        Harness.assertEquals("net.portscan", log.all().last().capability)
        Harness.assertEquals("sess-1", log.all().last().sessionId)
    }

    Harness.test("throwing action is audited and returns ACTION_FAILED") {
        val (gate, log, _) = cleanGate()
        val r = gate.guard(req()) { error("boom") }
        Harness.assertEquals(DenialReason.ACTION_FAILED, (r as com.sentinelnet.core.consent.ConsentResult.Denied).reason)
        Harness.assertEquals("ERROR", log.all().last().decision)
    }

    Harness.test("denials are audited with reason and target") {
        val (gate, log, _) = cleanGate()
        gate.guard(req(target = "192.168.1.2", d = dec())) { 1 }
        val e = log.all().last()
        Harness.assertEquals("DENIED", e.decision)
        Harness.assertEquals("192.168.1.2", e.target)
        Harness.assertContains(e.reason, "TARGET_MISMATCH")
    }

    Harness.section("target-validator") {
        Harness.test("RFC1918 + loopback + link-local + IPv6 ULA are local") {
            for (ip in listOf("10.0.0.1", "172.16.5.4", "172.31.255.254", "192.168.0.1",
                "127.0.0.1", "169.254.1.1", "100.64.0.1", "fe80::1", "fd00::1")) {
                Harness.assertTrue(NetworkMath.isPrivateOrLab(ip), ip)
            }
        }
        Harness.test("public, broadcast and multicast targets are not local") {
            Harness.assertTrue(!NetworkMath.isPrivateOrLab("8.8.8.8"))
            Harness.assertTrue(NetworkMath.isMulticastOrBroadcast("224.0.0.1"))
            Harness.assertTrue(NetworkMath.isMulticastOrBroadcast("255.255.255.255"))
            Harness.assertTrue(!TargetValidator.validate("255.255.255.255", AuthorizationScope.OWN_NETWORK, true, "long justification").allowed)
        }
        Harness.test("validator requires written justification for public targets") {
            val v = TargetValidator.validate("1.1.1.1", AuthorizationScope.AUTHORIZED_ENGAGEMENT, true,
                "Authorized penetration test, ticket #1234")
            Harness.assertTrue(v.allowed)
            Harness.assertEquals(com.sentinelnet.core.consent.TargetClass.PUBLIC, v.targetClass)
        }
    }

    Harness.section("network-math") {
        Harness.test("IPv4 round-trip") {
            Harness.assertEquals(3232235777L, NetworkMath.ipv4ToLong("192.168.1.1"))
            Harness.assertEquals("192.168.1.1", NetworkMath.longToIpv4(3232235777L))
            Harness.assertEquals(null, NetworkMath.ipv4ToLong("999.1.1.1"))
        }
        Harness.test("CIDR expansion and sweep guard") {
            Harness.assertEquals(listOf("192.168.1.1", "192.168.1.2"), NetworkMath.cidrHosts("192.168.1.0/30"))
            Harness.assertEquals(256L, NetworkMath.sweepSize("192.168.1.0/24"))
            Harness.assertEquals(16777216L, NetworkMath.sweepSize("10.0.0.0/8"))
            Harness.assertTrue(NetworkMath.cidrHosts("10.0.0.0/8").isEmpty())
        }
        Harness.test("IPv6 detection") {
            Harness.assertTrue(NetworkMath.looksLikeIpv6("fe80::1%wlan0"))
            Harness.assertTrue(NetworkMath.isValidIp("2001:db8::1"))
            Harness.assertTrue(!NetworkMath.isValidIp("not a host"))
        }
    }
}
