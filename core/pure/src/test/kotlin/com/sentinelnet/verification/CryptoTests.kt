package com.sentinelnet.verification

import com.sentinelnet.core.crypto.Bytes
import com.sentinelnet.core.crypto.EncodingTools
import com.sentinelnet.core.crypto.HashTools
import com.sentinelnet.core.crypto.Hmac
import com.sentinelnet.core.crypto.PassphraseAudit
import com.sentinelnet.core.crypto.PasswordGenerator
import com.sentinelnet.core.crypto.Pbkdf2
import com.sentinelnet.core.crypto.WpaPskLab

fun cryptoTests() = Harness.section("pbkdf2-rfc6070") {
    Harness.test("RFC 6070 vector 1 (c=1)") {
        Harness.assertEquals("0c60c80f961f0e71f3a9b524af6012062fe037a6",
            Bytes.toHex(Pbkdf2.hmacSha1("password".toByteArray(), "salt".toByteArray(), 1, 20), true))
    }
    Harness.test("RFC 6070 vector 2 (c=2)") {
        Harness.assertEquals("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
            Bytes.toHex(Pbkdf2.hmacSha1("password".toByteArray(), "salt".toByteArray(), 2, 20), true))
    }
    Harness.test("RFC 6070 vector 3 (c=4096)") {
        Harness.assertEquals("4b007901b765489abead49d926f721d065a429c1",
            Bytes.toHex(Pbkdf2.hmacSha1("password".toByteArray(), "salt".toByteArray(), 4096, 20), true))
    }
    Harness.test("RFC 6070 vector 4 (long salt, dkLen=25)") {
        Harness.assertEquals("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
            Bytes.toHex(Pbkdf2.hmacSha1(
                "passwordPASSWORDpassword".toByteArray(),
                "saltSALTsaltSALTsaltSALTsaltSALTsalt".toByteArray(), 4096, 25), true))
    }
    Harness.test("RFC 6070 vector 5 (embedded NUL, dkLen=16)") {
        Harness.assertEquals("56fa6aa75548099dcc37d7f03425e0c3",
            Bytes.toHex(Pbkdf2.hmacSha1("pass\u0000word".toByteArray(), "sa\u0000lt".toByteArray(), 4096, 16), true))
    }
    Harness.test("invalid parameters are rejected") {
        var threw = false
        try { Pbkdf2.hmacSha1(ByteArray(1), ByteArray(1), 0, 16) } catch (e: IllegalArgumentException) { threw = true }
        Harness.assertTrue(threw)
    }

    Harness.section("hmac-and-hash") {
        Harness.test("RFC 2202 HMAC-SHA1 vector") {
            Harness.assertEquals("b617318655057264e28bc0b6fb378c8ef146be00",
                Bytes.toHex(Hmac.sha1(ByteArray(20) { 0x0b }, "Hi There".toByteArray()), true))
        }
        Harness.test("SHA-256 / MD5 / HMAC-SHA256 digests") {
            Harness.assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                HashTools.sha256(ByteArray(0)))
            Harness.assertEquals("d41d8cd98f00b204e9800998ecf8427e", HashTools.md5(ByteArray(0)))
            Harness.assertEquals(64, HashTools.hmacSha256Hex("key".toByteArray(), "msg".toByteArray()).length)
        }
        Harness.test("hex/base64/url round-trip") {
            val data = "SentinelNet ✓ 123".toByteArray()
            Harness.assertEquals(Bytes.toHex(data, true), EncodingTools.hexEncode(data))
            Harness.assertTrue(Bytes.constantTimeEquals(data, EncodingTools.hexDecode(EncodingTools.hexEncode(data))))
            Harness.assertTrue(Bytes.constantTimeEquals(data, EncodingTools.base64Decode(EncodingTools.base64Encode(data))))
            Harness.assertEquals("a%20b%26c", EncodingTools.urlEncode("a b&c"))
            Harness.assertEquals("a b&c", EncodingTools.urlDecode("a%20b%26c"))
            Harness.assertEquals("a b&c", EncodingTools.urlDecode("a+b%26c"))
            Harness.assertEquals("SentinelNet%20%E2%9C%93", EncodingTools.urlEncode("SentinelNet ✓"))
            Harness.assertEquals("SentinelNet ✓", EncodingTools.urlDecode("SentinelNet%20%E2%9C%93"))
        }
        Harness.test("byte helpers and constant-time comparison") {
            Harness.assertEquals("0102ff", Bytes.toHex(byteArrayOf(1, 2, -1), true))
            Harness.assertTrue(Bytes.constantTimeEquals(ByteArray(16), ByteArray(16)))
            Harness.assertTrue(!Bytes.constantTimeEquals(ByteArray(16), ByteArray(17)))
            Harness.assertEquals(0x01020304L, Bytes.readU32be(Bytes.u32be(0x01020304), 0))
            Harness.assertTrue(Bytes.compareUnsigned(byteArrayOf(1), byteArrayOf(2)) < 0)
            Harness.assertTrue(Bytes.compareUnsigned(byteArrayOf(-1), byteArrayOf(1)) > 0)
        }
    }

    Harness.section("wpa-security-lab") {
        Harness.test("PMK matches independent PBKDF2 reference") {
            val pmk = WpaPskLab.derivePmk("SentinelLab", "correct horse battery staple")
            Harness.assertEquals(
                "f8daaf279deacd189ab78c7620e653acd6bdef95cf65824717b4d8c6d78819b6",
                Bytes.toHex(pmk, true))
            Harness.assertEquals(32, pmk.size)
        }
        Harness.test("PTK/KCK matches independent 802.11i PRF reference") {
            val pmk = WpaPskLab.derivePmk("SentinelLab", "correct horse battery staple")
            val ap = Bytes.fromMac("00:1A:2B:3C:4D:5E")
            val sta = Bytes.fromMac("7C:2E:BD:11:22:33")
            val an = ByteArray(32) { (it * 7 + 3).toByte() }
            val sn = ByteArray(32) { (it * 13 + 29).toByte() }
            val ptk = WpaPskLab.derivePtk(pmk, ap, sta, an, sn)
            Harness.assertEquals(64, ptk.size)
            Harness.assertEquals("99fbe53411cddf7ea31c5ae6e7c7c0f6", Bytes.toHex(ptk.copyOf(16), true))
        }
        Harness.test("WPA2 EAPOL MIC (HMAC-SHA1/128) matches reference") {
            val sample = testSample()
            val kck = WpaPskLab.derivePtk(
                WpaPskLab.derivePmk(sample.ssid, "correct horse battery staple"),
                sample.apMac, sample.staMac, sample.aNonce, sample.sNonce).copyOf(16)
            val mic = WpaPskLab.computeMic(2, kck, sample.eapolFrameWithZeroedMic)!!
            Harness.assertEquals("29a648ab499560057f32664f7e39647f", Bytes.toHex(mic, true))
        }
        Harness.test("WPA1 EAPOL MIC (HMAC-MD5) matches reference") {
            val sample = testSample(1)
            val kck = WpaPskLab.derivePtk(
                WpaPskLab.derivePmk(sample.ssid, "correct horse battery staple"),
                sample.apMac, sample.staMac, sample.aNonce, sample.sNonce).copyOf(16)
            val mic = WpaPskLab.computeMic(1, kck, sample.eapolFrameWithZeroedMic)!!
            Harness.assertEquals("61802f0566b78179e2972d942710ecb4", Bytes.toHex(mic, true))
        }
        Harness.test("unsupported key descriptor version is refused, not guessed") {
            Harness.assertEquals(null, WpaPskLab.computeMic(3, ByteArray(16), ByteArray(10)))
        }
        Harness.test("synthetic handshake verifies with its own passphrase") {
            val s = WpaPskLab.syntheticHandshake("LabNet", "Sunset-Raven-42!")
            Harness.assertTrue(s.synthetic)
            Harness.assertTrue(WpaPskLab.verify(s, "Sunset-Raven-42!").matched)
            Harness.assertTrue(!WpaPskLab.verify(s, "wrong-password").matched)
        }
        Harness.test("offline exercise finds a weak candidate in a user-supplied list") {
            val s = WpaPskLab.syntheticHandshake("LabNet", "password123")
            val candidates = sequenceOf("letmein", "admin", "password123", "something-else")
            val result = WpaPskLab.exercise(s, candidates)
            Harness.assertEquals("password123", result.found)
            Harness.assertEquals(3, result.tested)
            Harness.assertTrue(result.elapsedMs >= 0)
        }
        Harness.test("offline exercise reports no false positive") {
            val s = WpaPskLab.syntheticHandshake("LabNet", "Unlisted-Strong-Passphrase!")
            val result = WpaPskLab.exercise(s, sequenceOf("password", "12345678", "wifi1234"))
            Harness.assertEquals(null, result.found)
            Harness.assertEquals(3, result.tested)
        }
        Harness.test("lab caps are deliberately conservative") {
            Harness.assertTrue(WpaPskLab.MAX_CANDIDATES <= 200_000)
            Harness.assertTrue(WpaPskLab.MAX_LAB_MILLIS <= 30_000L)
        }
    }

    Harness.section("passphrase-and-generator") {
        Harness.test("common default passphrase is flagged as trivially weak") {
            val v = PassphraseAudit.audit("password123")
            Harness.assertTrue(v.isTriviallyWeak)
            Harness.assertEquals(0.0, v.entropyBits)
            Harness.assertTrue(v.issues.any { it.contains("well-known") })
            Harness.assertTrue(v.recommendations.any { it.contains("WPA3") })
        }
        Harness.test("strong random passphrase scores higher") {
            val weak = PassphraseAudit.audit("password123")
            val strong = PassphraseAudit.audit("V7!qzR2#kLm9@Tps4w")
            Harness.assertTrue(strong.entropyBits > weak.entropyBits)
            Harness.assertTrue(!strong.isTriviallyWeak)
        }
        Harness.test("CSPRNG generator produces distinct values with a symbol") {
            val a = PasswordGenerator.randomString()
            val b = PasswordGenerator.randomString()
            Harness.assertTrue(a != b)
            Harness.assertEquals(20, a.length)
            Harness.assertTrue(a.any { !it.isLetterOrDigit() })
            Harness.assertEquals(5, PasswordGenerator.passphrase(5).split("-").size)
            Harness.assertEquals(32, PasswordGenerator.randomBytes(32).size)
        }
    }
}

private fun testSample(kdv: Int = 2): WpaPskLab.HandshakeSample {
    val frame = ByteArray(95)
    frame[0] = 2; frame[3] = 3; frame[5] = 8
    val an = ByteArray(32) { (it * 7 + 3).toByte() }
    val sn = ByteArray(32) { (it * 13 + 29).toByte() }
    an.copyInto(frame, 17); sn.copyInto(frame, 49)
    val expected = if (kdv == 2) "29a648ab499560057f32664f7e39647f" else "61802f0566b78179e2972d942710ecb4"
    return WpaPskLab.HandshakeSample(
        ssid = "SentinelLab", apMac = Bytes.fromMac("00:1A:2B:3C:4D:5E"),
        staMac = Bytes.fromMac("7C:2E:BD:11:22:33"), aNonce = an, sNonce = sn,
        eapolFrameWithZeroedMic = frame, expectedMic = Bytes.fromHex(expected),
        keyDescriptorVersion = kdv, synthetic = true)
}
