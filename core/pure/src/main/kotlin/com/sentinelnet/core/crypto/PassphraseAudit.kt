package com.sentinelnet.core.crypto

import kotlin.math.log2

/**
 * Defensive passphrase auditing. The user types their OWN passphrase; nothing
 * is transmitted, stored in plaintext, or compared against a remote service.
 */
object PassphraseAudit {

    /** Small seed list of router defaults / common mistakes. Not a cracking dictionary. */
    val COMMON_WEAK = setOf(
        "password", "password123", "12345678", "123456789", "1234567890", "qwertyuiop",
        "admin", "admin123", "letmein", "welcome", "welcome1", "iloveyou", "sunshine",
        "princess", "dragon", "monkey", "football", "baseball", "default", "changeme",
        "wifi1234", "wifipassword", "internet", "router", "1234abcd", "abcd1234",
        "qwerty123", "pass1234", "00000000", "11111111", "88888888", "test1234"
    )

    data class Verdict(
        val entropyBits: Double,
        val rating: String,
        val issues: List<String>,
        val recommendations: List<String>,
        val isTriviallyWeak: Boolean
    )

    fun audit(passphrase: String): Verdict {
        val issues = mutableListOf<String>()
        val recs = mutableListOf<String>()
        val lower = passphrase.lowercase()

        if (passphrase.length < 8) issues += "WPA2-PSK requires at least 8 characters."
        if (passphrase.length < 12) issues += "Shorter than 12 characters; offline guessing is cheap."
        if (lower in COMMON_WEAK) issues += "This is a well-known default/guessable passphrase."
        if (passphrase.toSet().size <= 3) issues += "Uses too few distinct characters."
        if (Regex("""(\d)\1{3,}""").containsMatchIn(passphrase)) issues += "Contains a long repeated digit run."
        if (Regex("""(19|20)\d{2}""").containsMatchIn(passphrase)) issues += "Contains a year, which is easy to guess."
        if (Regex("""^\d{8,}$""").matches(passphrase)) issues += "All-numeric passphrase."
        if (passphrase.none { it.isUpperCase() }) issues += "No uppercase letters." 
        if (passphrase.none { it.isDigit() }) issues += "No digits."
        if (passphrase.none { !it.isLetterOrDigit() }) issues += "No symbols."

        recs += "Use 16+ characters or a 5-6 word Diceware-style passphrase."
        recs += "Generate it with a CSPRNG (SentinelNet's password generator) and store it in a password manager."
        recs += "Prefer WPA3-SAE: it resists offline dictionary attacks even with a weak passphrase."
        recs += "Disable WPS PIN and enable Protected Management Frames (PMF)."

        val pool = (if (passphrase.any { it.isLowerCase() }) 26 else 0) +
            (if (passphrase.any { it.isUpperCase() }) 26 else 0) +
            (if (passphrase.any { it.isDigit() }) 10 else 0) +
            (if (passphrase.any { !it.isLetterOrDigit() }) 32 else 0)
        val entropy = if (pool <= 1) 0.0 else passphrase.length * log2(pool.toDouble())
        val effective = if (lower in COMMON_WEAK) 0.0 else entropy
        val rating = when {
            effective < 25 -> "Very weak"
            effective < 40 -> "Weak"
            effective < 60 -> "Moderate"
            effective < 80 -> "Strong"
            else -> "Very strong"
        }
        return Verdict(effective, rating, issues, recs, lower in COMMON_WEAK || passphrase.length < 8)
    }
}
