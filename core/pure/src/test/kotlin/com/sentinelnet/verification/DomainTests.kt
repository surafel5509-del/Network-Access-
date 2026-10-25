package com.sentinelnet.verification

import com.sentinelnet.core.domain.ChannelAdvisor
import com.sentinelnet.core.domain.CveHintMatcher
import com.sentinelnet.core.domain.DeviceFingerprinter
import com.sentinelnet.core.domain.OuiLookup
import com.sentinelnet.core.domain.PortRisk
import com.sentinelnet.core.domain.RogueApDetector
import com.sentinelnet.core.domain.SecurityScorer
import com.sentinelnet.core.domain.WifiSecurityAuditor
import com.sentinelnet.core.model.Band
import com.sentinelnet.core.model.DiscoveredDevice
import com.sentinelnet.core.model.Finding
import com.sentinelnet.core.model.PortResult
import com.sentinelnet.core.model.PortState
import com.sentinelnet.core.model.ScoreCategory
import com.sentinelnet.core.model.Severity
import com.sentinelnet.core.model.WifiChannels
import com.sentinelnet.core.model.WifiNetwork
import com.sentinelnet.core.model.WifiSecurity
import com.sentinelnet.core.model.WifiStandard

private fun net(
    ssid: String, bssid: String, rssi: Int = -60, freq: Int = 2437,
    sec: WifiSecurity = WifiSecurity.WPA2, wps: Boolean = false, vendor: String? = null
) = WifiNetwork(ssid, bssid, rssi, freq, 20, sec, WifiStandard.WIFI_6, wps,
    vendor = vendor, timestampMillis = 1000L)

fun domainTests() = Harness.section("wifi-channels") {
    Harness.test("2.4/5/6 GHz frequency-to-channel mapping") {
        Harness.assertEquals(1, WifiChannels.frequencyToChannel(2412))
        Harness.assertEquals(6, WifiChannels.frequencyToChannel(2437))
        Harness.assertEquals(11, WifiChannels.frequencyToChannel(2462))
        Harness.assertEquals(14, WifiChannels.frequencyToChannel(2484))
        Harness.assertEquals(36, WifiChannels.frequencyToChannel(5180))
        Harness.assertEquals(1, WifiChannels.frequencyToChannel(5955))
    }
    Harness.test("band classification") {
        Harness.assertEquals(Band.GHZ_2_4, Band.fromFrequencyMhz(2437))
        Harness.assertEquals(Band.GHZ_5, Band.fromFrequencyMhz(5180))
        Harness.assertEquals(Band.GHZ_6, Band.fromFrequencyMhz(6135))
        Harness.assertEquals(Band.UNKNOWN, Band.fromFrequencyMhz(900))
    }
    Harness.test("2.4 GHz recommendation is always a non-overlapping channel") {
        val advisor = ChannelAdvisor()
        val networks = listOf(
            net("a", "00:1A:2B:00:00:01", -45, 2412),
            net("b", "00:1A:2B:00:00:02", -50, 2412),
            net("c", "00:1A:2B:00:00:03", -55, 2437)
        )
        val rec = advisor.recommend(Band.GHZ_2_4, networks)
        Harness.assertTrue(rec.channel in WifiChannels.NON_OVERLAPPING_2_4, "got ${rec.channel}")
        Harness.assertEquals(11, rec.channel)
        Harness.assertContains(rec.reason, "congestion")
    }
    Harness.test("congestion decreases as we move away from busy channels") {
        val advisor = ChannelAdvisor()
        val busy = listOf(net("a", "00:1A:2B:00:00:01", -35, 2412))
        val loads = advisor.analyze(busy).filter { it.band == Band.GHZ_2_4 }
        val at1 = loads.first { it.channel == 1 }.weightedCongestion
        val at11 = loads.first { it.channel == 11 }.weightedCongestion
        Harness.assertTrue(at1 > at11, "expected ch1 ($at1) > ch11 ($at11)")
    }
    Harness.test("empty band returns a clear-channel recommendation") {
        val rec = ChannelAdvisor().recommend(Band.GHZ_5, emptyList())
        Harness.assertEquals(100.0, rec.score)
        Harness.assertContains(rec.reason, "clear")
    }
    Harness.test("vendor annotation refuses randomized BSSIDs") {
        val advisor = ChannelAdvisor()
        Harness.assertEquals("Cisco Systems", advisor.annotateVendor(net("x", "00:1A:2B:11:22:33")))
        Harness.assertEquals(null, advisor.annotateVendor(net("x", "02:1A:2B:11:22:33")))
    }

    Harness.section("wifi-audit") {
        Harness.test("open / WEP / WPA1 / WPS produce findings by severity") {
            val networks = listOf(
                net("open", "00:1A:2B:00:00:01", sec = WifiSecurity.OPEN),
                net("wep", "00:1A:2B:00:00:02", sec = WifiSecurity.WEP),
                net("wpa", "00:1A:2B:00:00:03", sec = WifiSecurity.WPA),
                net("wps", "00:1A:2B:00:00:04", sec = WifiSecurity.WPS)
            )
            val findings = WifiSecurityAuditor().audit(networks, 1234L)
            Harness.assertTrue(findings.any { it.id.contains("wifi.open") && it.severity == Severity.CRITICAL })
            Harness.assertTrue(findings.any { it.severity == Severity.CRITICAL && it.id.contains("wep") })
            Harness.assertTrue(findings.all { it.category == ScoreCategory.WIFI })
            Harness.assertTrue(findings.all { it.remediation.isNotBlank() })
            Harness.assertTrue(findings.all { it.detectedAtMillis == 1234L })
        }
        Harness.test("WPA3 network is not flagged as insecure") {
            val findings = WifiSecurityAuditor().audit(listOf(net("secure", "00:1A:2B:00:00:09",
                sec = WifiSecurity.WPA3)))
            Harness.assertTrue(findings.none { it.severity >= Severity.HIGH })
        }
        Harness.test("mixed vendor OUIs for one SSID raise an evil-twin hint") {
            val networks = listOf(
                net("CafeWiFi", "00:1A:2B:00:00:01", -55),
                net("CafeWiFi", "C0:25:E9:00:00:02", -60)
            )
            val findings = RogueApDetector().detect(networks)
            Harness.assertTrue(findings.any { it.id.contains("eviltwin.vendor") })
            Harness.assertContains(findings.first { it.id.contains("eviltwin.vendor") }.detail, "Verify")
        }
        Harness.test("unusually strong clone is flagged") {
            val networks = listOf(
                net("Office", "00:1A:2B:00:00:01", -70),
                net("Office", "00:1A:2B:00:00:02", -72),
                net("Office", "00:1A:2B:00:00:03", -30)
            )
            Harness.assertTrue(RogueApDetector().detect(networks).any { it.id.contains("eviltwin.signal") })
        }
    }

    Harness.section("scoring") {
        Harness.test("no findings = 100 / grade A") {
            val s = SecurityScorer.score(emptyList(), 42L)
            Harness.assertEquals(100, s.overall)
            Harness.assertEquals("A", s.grade)
            Harness.assertEquals(ScoreCategory.entries.size, s.categories.size)
        }
        Harness.test("score is deterministic and order-independent") {
            val a = Finding("a", "A", "d", Severity.HIGH, ScoreCategory.WIFI, "r")
            val b = Finding("b", "B", "d", Severity.CRITICAL, ScoreCategory.NETWORK, "r")
            val s1 = SecurityScorer.score(listOf(a, b), 1L)
            val s2 = SecurityScorer.score(listOf(b, a), 1L)
            Harness.assertEquals(s1.overall, s2.overall)
            Harness.assertEquals(s1.inputFingerprint, s2.inputFingerprint)
            Harness.assertTrue(s1.findings.first().severity == Severity.CRITICAL)
        }
        Harness.test("score clamps at zero and findings are weighted") {
            val many = (1..20).map { Finding("f$it", "F", "d", Severity.CRITICAL, ScoreCategory.DEVICE, "r") }
            Harness.assertEquals(0, SecurityScorer.score(many).categories.first { it.category == ScoreCategory.DEVICE }.rawScore)
            Harness.assertTrue(SecurityScorer.score(many).overall < 100)
        }
        Harness.test("fingerprint changes when a finding changes") {
            val a = Finding("a", "A", "d", Severity.HIGH, ScoreCategory.WIFI, "r")
            val b = a.copy(severity = Severity.LOW)
            Harness.assertTrue(SecurityScorer.fingerprint(listOf(a)) != SecurityScorer.fingerprint(listOf(b)))
        }
        Harness.test("remediation plan is sorted by severity") {
            val list = listOf(
                Finding("low", "L", "", Severity.LOW, ScoreCategory.WIFI, "fix low"),
                Finding("crit", "C", "", Severity.CRITICAL, ScoreCategory.WIFI, "fix crit")
            )
            Harness.assertContains(SecurityScorer.prioritizedRemediation(list).first(), "CRITICAL")
        }
    }

    Harness.section("exposure-and-hints") {
        Harness.test("dangerous open ports are scored") {
            val results = listOf(
                PortResult("192.168.1.1", 23, "tcp", PortState.OPEN),
                PortResult("192.168.1.1", 445, "tcp", PortState.OPEN),
                PortResult("192.168.1.1", 443, "tcp", PortState.OPEN),
                PortResult("192.168.1.1", 22, "tcp", PortState.CLOSED)
            )
            val findings = PortRisk.assess(results)
            Harness.assertEquals(3, findings.size)
            Harness.assertTrue(findings.any { it.severity == Severity.CRITICAL })
            Harness.assertTrue(PortRisk.exposure(results) < 100)
            Harness.assertTrue(PortRisk.TOP_100.size >= 80)
        }
        Harness.test("CVE hints are passive, labelled and link to NVD") {
            val hints = CveHintMatcher().match("Apache", "2.4.49", "Apache/2.4.49 (Unix)", "192.168.1.5")
            Harness.assertTrue(hints.isNotEmpty())
            Harness.assertContains(hints.first().detail, "NOT a confirmed vulnerability")
            Harness.assertContains(hints.first().referenceUrl ?: "", "nvd.nist.gov")
        }
        Harness.test("device fingerprinting uses passive signals") {
            val router = DiscoveredDevice("192.168.1.1", "00:1A:2B:00:00:01", hostname = "OpenWrt.lan")
            Harness.assertEquals(com.sentinelnet.core.model.DeviceType.ROUTER, DeviceFingerprinter.guessType(router))
            val enriched = DeviceFingerprinter.enrich(router)
            Harness.assertEquals("Cisco Systems", enriched.vendor)
            Harness.assertContains(DeviceFingerprinter.guessOsFromTtl(64), "Linux")
            Harness.assertContains(DeviceFingerprinter.guessOsFromTtl(128), "Windows")
        }
        Harness.test("OUI lookup handles randomized/local bits") {
            val oui = OuiLookup()
            Harness.assertTrue(oui.isRandomized("02:11:22:33:44:55"))
            Harness.assertTrue(!oui.isRandomized("00:1A:2B:33:44:55"))
            Harness.assertEquals("Apple", oui.lookup("3C:22:FB:AA:BB:CC"))
            Harness.assertEquals(null, oui.lookup("garbage"))
        }
    }
}
