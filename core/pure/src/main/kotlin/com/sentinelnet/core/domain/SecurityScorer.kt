package com.sentinelnet.core.domain

import com.sentinelnet.core.model.CategoryScore
import com.sentinelnet.core.model.Finding
import com.sentinelnet.core.model.ScoreCategory
import com.sentinelnet.core.model.SecurityScore
import java.security.MessageDigest

/**
 * Deterministic, reproducible 0-100 score.
 *
 * Each category starts at 100 and loses `severity.weight` points per finding.
 * Categories are combined with fixed weights (see ScoreCategory). The same set
 * of findings always produces the same score and the same input fingerprint,
 * which is a requirement in the acceptance criteria ("accurate and reproducible").
 */
object SecurityScorer {

    fun score(
        findings: List<Finding>,
        computedAtMillis: Long = 0L,
        inputFingerprint: String = fingerprint(findings)
    ): SecurityScore {
        val categories = ScoreCategory.entries.map { category ->
            val inCategory = findings.filter { it.category == category }
            val deduction = inCategory.sumOf { it.severity.weight }
            val raw = (100 - deduction).coerceIn(0, 100)
            CategoryScore(
                category = category,
                rawScore = raw,
                findingCount = inCategory.size,
                weightedContribution = raw * category.weight / ScoreCategory.TOTAL_WEIGHT
            )
        }
        val overall = categories.sumOf { it.weightedContribution }
            .let { kotlin.math.round(it).toInt() }
            .coerceIn(0, 100)
        return SecurityScore(
            overall = overall,
            categories = categories,
            findings = findings.sortedWith(compareByDescending<Finding> { it.severity.weight }.thenBy { it.id }),
            computedAtMillis = computedAtMillis,
            inputFingerprint = inputFingerprint
        )
    }

    /** Stable digest over the semantic content of the findings, not their order. */
    fun fingerprint(findings: List<Finding>): String {
        val canonical = findings
            .map { "${it.id}|${it.severity.name}|${it.category.name}" }
            .sorted()
            .joinToString("\n")
        val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8))
        return digest.take(8).joinToString("") { "%02x".format(it) }
    }

    /** Findings sorted by impact, for the remediation plan in the PDF/JSON report. */
    fun prioritizedRemediation(findings: List<Finding>): List<String> = findings
        .sortedWith(compareByDescending<Finding> { it.severity.weight }.thenBy { it.id })
        .map { "[${it.severity.name}] ${it.title} — ${it.remediation}" }
}
