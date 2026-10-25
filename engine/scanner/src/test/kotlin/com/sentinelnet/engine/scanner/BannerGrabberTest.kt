package com.sentinelnet.engine.scanner

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class BannerGrabberTest {
    @Test fun `service names are mapped`() {
        assertEquals("SSH", BannerGrabber.serviceFor(22))
        assertEquals("HTTPS", BannerGrabber.serviceFor(443))
        assertNull(BannerGrabber.serviceFor(65000))
    }

    @Test fun `version is extracted from a banner`() {
        assertEquals("2.4.49", BannerGrabber.versionFrom("Apache/2.4.49 (Unix)"))
        assertEquals("9.2p1", BannerGrabber.versionFrom("OpenSSH_9.2p1 Debian"))
        assertNull(BannerGrabber.versionFrom("no version here"))
    }

    @Test fun `TLS ports are excluded from plaintext banner probes`() {
        assertEquals(true, TcpConnectScanner.TLS_PORTS.contains(443))
        assertEquals(false, TcpConnectScanner.TLS_PORTS.contains(80))
    }
}
