package com.sentinelnet.core.crypto

import java.util.Base64

/**
 * Module E3 encoding helpers.
 *
 * `urlEncode` implements RFC 3986 percent-encoding (space -> %20), NOT HTML
 * form encoding (space -> '+'). java.net.URLEncoder is form-only and would
 * produce wrong output for URL paths — a mistake worth avoiding in a tool that
 * generates share links and proxy rules.
 */
object EncodingTools {
    fun base64Encode(input: ByteArray): String = Base64.getEncoder().encodeToString(input)
    fun base64Decode(input: String): ByteArray = Base64.getDecoder().decode(input)
    fun hexEncode(input: ByteArray): String = Bytes.toHex(input, lowerCase = true)
    fun hexDecode(input: String): ByteArray = Bytes.fromHex(input)

    private const val UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    private val HEX_UPPER = "0123456789ABCDEF".toCharArray()

    fun urlEncode(input: String): String {
        val bytes = input.toByteArray(Charsets.UTF_8)
        return buildString(bytes.size * 2) {
            for (b in bytes) {
                val c = b.toInt() and 0xFF
                if (c < 128 && c.toChar() in UNRESERVED) append(c.toChar())
                else { append('%'); append(HEX_UPPER[c ushr 4]); append(HEX_UPPER[c and 0x0F]) }
            }
        }
    }

    /** Accepts both RFC 3986 (%20) and form-encoded (+) spaces. */
    fun urlDecode(input: String): String {
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < input.length) {
            when (val c = input[i]) {
                '%' -> {
                    if (i + 2 >= input.length) throw IllegalArgumentException("Truncated percent-escape")
                    val hi = Character.digit(input[i + 1], 16)
                    val lo = Character.digit(input[i + 2], 16)
                    if (hi < 0 || lo < 0) throw IllegalArgumentException("Invalid percent-escape")
                    out.write((hi shl 4) or lo)
                    i += 3
                }
                '+' -> { out.write(' '.code); i++ }
                else -> { out.write(c.code); i++ }
            }
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }
}
