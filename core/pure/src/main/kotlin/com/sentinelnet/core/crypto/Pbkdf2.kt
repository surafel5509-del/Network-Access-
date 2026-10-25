package com.sentinelnet.core.crypto

/**
 * PBKDF2-HMAC-SHA1 (RFC 2898 / PKCS #5 v2), implemented from first principles.
 *
 * Why not SecretKeyFactory("PBKDF2WithHmacSHA1")? Two reasons: (1) the Security
 * Lab is a teaching tool and students should be able to read the actual F()
 * function; (2) a pure implementation behaves identically on all API levels
 * and on the JVM, so the conformance suite can cross-check it against Python's
 * hashlib.pbkdf2_hmac. Production hot paths use the native Rust implementation.
 */
object Pbkdf2 {
    private const val HASH_LENGTH = 20 // SHA-1 output

    fun hmacSha1(
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        derivedKeyLength: Int
    ): ByteArray {
        require(iterations > 0) { "iterations must be positive" }
        require(derivedKeyLength > 0) { "derivedKeyLength must be positive" }
        val blocks = (derivedKeyLength + HASH_LENGTH - 1) / HASH_LENGTH
        val out = ByteArray(blocks * HASH_LENGTH)
        for (block in 1..blocks) {
            val saltWithCounter = Bytes.concat(salt, Bytes.u32be(block))
            var u = Hmac.sha1(password, saltWithCounter)
            val t = u.copyOf()
            for (iteration in 2..iterations) {
                u = Hmac.sha1(password, u)
                for (i in t.indices) t[i] = (t[i].toInt() xor u[i].toInt()).toByte()
            }
            t.copyInto(out, (block - 1) * HASH_LENGTH)
        }
        return if (derivedKeyLength == out.size) out else out.copyOf(derivedKeyLength)
    }

    /** Generic variant used by the passphrase-strength demo. */
    fun hmacSha256(password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
        require(iterations > 0 && dkLen > 0)
        val hLen = 32
        val blocks = (dkLen + hLen - 1) / hLen
        val out = ByteArray(blocks * hLen)
        for (block in 1..blocks) {
            var u = Hmac.sha256(password, Bytes.concat(salt, Bytes.u32be(block)))
            val t = u.copyOf()
            for (iteration in 2..iterations) {
                u = Hmac.sha256(password, u)
                for (i in t.indices) t[i] = (t[i].toInt() xor u[i].toInt()).toByte()
            }
            t.copyInto(out, (block - 1) * hLen)
        }
        return if (dkLen == out.size) out else out.copyOf(dkLen)
    }
}
