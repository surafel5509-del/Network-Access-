package com.sentinelnet.engine.wifi

import com.sentinelnet.core.model.WifiSecurity
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class WifiCapabilitiesParserTest {
    @Test fun `WPA3 SAE is detected before WPA2`() {
        assertEquals(WifiSecurity.WPA3, WifiCapabilitiesParser.parse("[WPA3-SAE-CCMP][ESS]"))
        assertEquals(WifiSecurity.WPA3, WifiCapabilitiesParser.parse("[SAE][ESS]"))
    }

    @Test fun `enterprise and OWE variants`() {
        assertEquals(WifiSecurity.WPA2_ENTERPRISE, WifiCapabilitiesParser.parse("[WPA2-EAP-CCMP][ESS]"))
        assertEquals(WifiSecurity.WPA3_ENTERPRISE, WifiCapabilitiesParser.parse("[SUITE_B_192][ESS]"))
        assertEquals(WifiSecurity.OWE, WifiCapabilitiesParser.parse("[OWE][ESS]"))
    }

    @Test fun `legacy and open networks`() {
        assertEquals(WifiSecurity.WPA2, WifiCapabilitiesParser.parse("[WPA2-PSK-CCMP][WPS][ESS]"))
        assertEquals(WifiSecurity.WPA, WifiCapabilitiesParser.parse("[WPA-PSK-TKIP][ESS]"))
        assertEquals(WifiSecurity.WEP, WifiCapabilitiesParser.parse("[WEP][ESS]"))
        assertEquals(WifiSecurity.OPEN, WifiCapabilitiesParser.parse("[ESS]"))
    }

    @Test fun `WPS is reported independently of the primary security type`() {
        assertTrue(WifiCapabilitiesParser.hasWps("[WPA2-PSK-CCMP][WPS][ESS]"))
        assertEquals(WifiSecurity.WPA2, WifiCapabilitiesParser.parse("[WPA2-PSK-CCMP][WPS][ESS]"))
    }
}
