package com.sentinelnet.core.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Thin JCA facade. Uses hardware/conscrypt providers on Android automatically. */
object Hmac {
    private fun compute(algorithm: String, key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(key, algorithm))
        return mac.doFinal(data)
    }

    fun sha1(key: ByteArray, data: ByteArray): ByteArray = compute("HmacSHA1", key, data)
    fun sha256(key: ByteArray, data: ByteArray): ByteArray = compute("HmacSHA256", key, data)
    fun md5(key: ByteArray, data: ByteArray): ByteArray = compute("HmacMD5", key, data)
}
