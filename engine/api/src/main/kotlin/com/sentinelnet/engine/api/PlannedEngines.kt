package com.sentinelnet.engine.api

import com.sentinelnet.core.consent.Capability
import com.sentinelnet.core.model.DiscoveredDevice
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow

/**
 * Explicit, documented placeholders. Returning "not implemented" with a phase
 * reference is a deliberate design decision: the UI can list the full product
 * surface without pretending a feature works. Replaced incrementally per phase.
 */
class PlannedBleEngine : PlannedEngine("ble", "Bluetooth / BLE", Capability.WIFI_SCAN, "Phase 5"), BleEngine {
    override fun observeDevices(): Flow<DiscoveredDevice> = emptyFlow()
    override suspend fun exploreGatt(mac: String): Result<List<String>> = Result.success(emptyList())
}

class PlannedNfcEngine : PlannedEngine("nfc", "NFC", Capability.WIFI_SCAN, "Phase 5"), NfcEngine {
    override fun tagTechs(): List<String> = emptyList()
    override fun ndefSupported(): Boolean = false
}

class PlannedCellularEngine : PlannedEngine("cellular", "Cellular", Capability.WIFI_SCAN, "Phase 5"), CellularEngine {
    override fun observeCellInfo(): Flow<CellularEngine.CellInfo> = emptyFlow()
}

class PlannedWifiDirectEngine : PlannedEngine("p2p", "Wi-Fi Direct", Capability.WIFI_SCAN, "Phase 5"), WifiDirectEngine {
    override fun observePeers(): Flow<DiscoveredDevice> = emptyFlow()
}

class PlannedEthernetEngine : PlannedEngine("ethernet", "USB Ethernet", Capability.WIFI_SCAN, "Phase 5"), EthernetEngine {
    override fun interfaceList(): List<String> = emptyList()
}

class PlannedFirewallEngine : PlannedEngine("firewall", "Firewall", Capability.FIREWALL_CHANGE, "Phase 3"), FirewallEngine {
    override fun blockedPackages(): Set<String> = emptySet()
}

class PlannedAutomationEngine : PlannedEngine("automation", "Automation", Capability.WIFI_SCAN, "Phase 7"), AutomationEngine {
    override fun scripts(): List<String> = emptyList()
}

class PlannedServerEngine : PlannedEngine("server", "Server suite", Capability.SERVER_START, "Phase 6"), ServerEngine {
    override fun runningServers(): List<String> = emptyList()
}

class PlannedMessagingEngine : PlannedEngine("messaging", "Offline messaging", Capability.WIFI_SCAN, "Phase 6"), MessagingEngine {
    override fun connectedPeers(): List<String> = emptyList()
}

class PlannedDeviceManagerEngine : PlannedEngine("device-manager", "App manager", Capability.WIFI_SCAN, "Phase 8"), DeviceManagerEngine {
    override fun installedPackages(): List<String> = emptyList()
}
