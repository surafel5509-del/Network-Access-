package com.sentinelnet.core.domain

import com.sentinelnet.core.model.Finding
import com.sentinelnet.core.model.PortResult
import com.sentinelnet.core.model.PortState
import com.sentinelnet.core.model.ScoreCategory
import com.sentinelnet.core.model.Severity

/** Open-port risk scoring. Advisory only — never exploits the service. */
object PortRisk {

    data class Rule(val port: Int, val service: String, val severity: Severity, val advice: String)

    val RULES: Map<Int, Rule> = listOf(
        Rule(21, "FTP", Severity.HIGH, "FTP sends credentials in cleartext; use SFTP or disable it."),
        Rule(23, "Telnet", Severity.CRITICAL, "Unauthenticated cleartext shell. Disable immediately."),
        Rule(25, "SMTP", Severity.MEDIUM, "Check for an open relay and enforce STARTTLS."),
        Rule(53, "DNS", Severity.LOW, "Restrict recursion to LAN clients; enable DNSSEC validation."),
        Rule(80, "HTTP", Severity.INFO, "Prefer HTTPS with HSTS; check for default admin pages."),
        Rule(110, "POP3", Severity.MEDIUM, "Require TLS; prefer IMAPS."),
        Rule(139, "NetBIOS", Severity.HIGH, "SMBv1/NetBIOS should be disabled on untrusted networks."),
        Rule(143, "IMAP", Severity.MEDIUM, "Require TLS on 993 instead."),
        Rule(161, "SNMP", Severity.HIGH, "Default community strings leak device details; change or disable."),
        Rule(389, "LDAP", Severity.MEDIUM, "Require LDAPS/StartTLS and strong bind credentials."),
        Rule(443, "HTTPS", Severity.INFO, "Audit TLS version, cipher suites and certificate validity."),
        Rule(445, "SMB", Severity.CRITICAL, "SMB on a network perimeter is a prime ransomware vector."),
        Rule(1433, "MSSQL", Severity.HIGH, "Never expose a database server to untrusted clients."),
        Rule(1521, "Oracle DB", Severity.HIGH, "Restrict to application hosts."),
        Rule(2049, "NFS", Severity.HIGH, "NFS without Kerberos exposes filesystem data."),
        Rule(3306, "MySQL", Severity.HIGH, "Bind to localhost or require TLS + strong accounts."),
        Rule(3389, "RDP", Severity.HIGH, "Restrict by firewall; enable NLA and MFA."),
        Rule(5432, "PostgreSQL", Severity.HIGH, "Use pg_hba.conf restrictions and TLS."),
        Rule(5900, "VNC", Severity.HIGH, "VNC often has weak or no authentication; tunnel it."),
        Rule(6379, "Redis", Severity.CRITICAL, "An unauthenticated Redis allows remote code execution."),
        Rule(8080, "HTTP-alt", Severity.LOW, "Check management interfaces for default credentials."),
        Rule(8443, "HTTPS-alt", Severity.LOW, "Verify certificate and admin authentication."),
        Rule(9200, "Elasticsearch", Severity.CRITICAL, "Unauthenticated clusters leak all indexed data."),
        Rule(11211, "Memcached", Severity.CRITICAL, "UDP amplification risk; bind to loopback."),
        Rule(27017, "MongoDB", Severity.CRITICAL, "Many legacy installs have no authentication enabled.")
    ).associateBy { it.port }

    val TOP_100: List<Int> = listOf(
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 67, 68, 69, 79, 80, 81, 82, 83, 84, 85,
        88, 89, 90, 99, 110, 111, 113, 119, 123, 135, 139, 143, 161, 179, 194, 199, 389,
        427, 443, 444, 445, 465, 500, 514, 515, 520, 523, 530, 548, 554, 587, 593, 623,
        626, 631, 636, 646, 873, 902, 989, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
        1080, 1194, 1433, 1434, 1521, 1701, 1720, 1723, 1812, 1813, 1883, 1900, 2049,
        2082, 2083, 2121, 2181, 2375, 2376, 3000, 3128, 3268, 3306, 3389, 3690, 4369,
        4443, 5000, 5060, 5432, 5601, 5672, 5900, 5984, 6379, 6443, 8000, 8008, 8080
    )

    fun assess(results: List<PortResult>, nowMillis: Long = 0L): List<Finding> =
        results.filter { it.state == PortState.OPEN && RULES.containsKey(it.port) }
            .map { r ->
                val rule = RULES.getValue(r.port)
                Finding(
                    id = "port.${r.target}.${r.port}",
                    title = "${rule.service} (${r.port}) open on ${r.target}",
                    detail = "Port ${r.port}/${r.protocol} is reachable. ${rule.advice}",
                    severity = rule.severity,
                    category = ScoreCategory.NETWORK,
                    remediation = rule.advice,
                    evidence = mapOf(
                        "port" to r.port.toString(), "protocol" to r.protocol,
                        "banner" to (r.banner ?: ""), "target" to r.target
                    ),
                    detectedAtMillis = nowMillis
                )
            }

    /** A rough 0-100 exposure measure for the discovery screen. */
    fun exposure(results: List<PortResult>): Int {
        val open = results.count { it.state == PortState.OPEN }
        val penalty = results.filter { it.state == PortState.OPEN }
            .sumOf { RULES[it.port]?.severity?.weight ?: 1 }
        return (100 - penalty - open / 2).coerceIn(0, 100)
    }
}
