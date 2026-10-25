package com.sentinelnet.core.crypto

import java.security.MessageDigest
import java.security.SecureRandom

/** Module E3 (offline crypto utilities). BLAKE2 is added on Android via BouncyCastle. */
object HashTools {
    fun md5(input: ByteArray): String = digest("MD5", input)
    fun sha1(input: ByteArray): String = digest("SHA-1", input)
    fun sha256(input: ByteArray): String = digest("SHA-256", input)
    fun sha512(input: ByteArray): String = digest("SHA-512", input)
    fun hmacSha256Hex(key: ByteArray, input: ByteArray): String = Bytes.toHex(Hmac.sha256(key, input), true)

    private fun digest(algorithm: String, input: ByteArray): String =
        Bytes.toHex(MessageDigest.getInstance(algorithm).digest(input), lowerCase = true)
}

object PasswordGenerator {
    private val random = SecureRandom()
    private const val ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#\$%^&*-_=+?"
    private const val ALPHANUMERIC_LENGTH = 57
    val WORDS = listOf(
        "amber", "anchor", "atlas", "birch", "canyon", "cedar", "cipher", "comet", "coral",
        "delta", "ember", "falcon", "forest", "granite", "harbor", "ivory", "jupiter", "lantern",
        "meadow", "nebula", "onyx", "orbit", "pebble", "quartz", "raven", "saffron", "thicket",
        "umber", "velvet", "willow", "zephyr", "signal", "packet", "beacon", "sentry", "radius"
    )

    fun randomString(length: Int = 20): String {
        require(length in 8..128)
        val base = buildString(length) {
            repeat(length) { append(ALPHABET[random.nextInt(ALPHANUMERIC_LENGTH)]) }
        }
        // Guarantee at least one symbol so common password policies are satisfied.
        val pos = random.nextInt(base.length)
        val symbol = ALPHABET[random.nextInt(ALPHABET.length - ALPHANUMERIC_LENGTH) + ALPHANUMERIC_LENGTH]
        return base.substring(0, pos) + symbol + base.substring(pos + 1)
    }

    fun passphrase(wordCount: Int = 5, separator: String = "-"): String {
        require(wordCount in 3..10)
        return (1..wordCount).joinToString(separator) { WORDS[random.nextInt(WORDS.size)] }
    }

    fun randomBytes(size: Int): ByteArray = ByteArray(size).also { random.nextBytes(it) }
}
