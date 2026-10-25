package com.sentinelnet.app.di

import com.sentinelnet.engine.api.BleEngine
import com.sentinelnet.engine.api.CaptureEngine
import com.sentinelnet.engine.api.CellularEngine
import com.sentinelnet.engine.api.DeviceDiscoveryEngine
import com.sentinelnet.engine.api.EthernetEngine
import com.sentinelnet.engine.api.NetworkToolsEngine
import com.sentinelnet.engine.api.PortScanEngine
import com.sentinelnet.engine.api.PlannedAutomationEngine
import com.sentinelnet.engine.api.PlannedBleEngine
import com.sentinelnet.engine.api.PlannedCellularEngine
import com.sentinelnet.engine.api.PlannedDeviceManagerEngine
import com.sentinelnet.engine.api.PlannedEthernetEngine
import com.sentinelnet.engine.api.PlannedFirewallEngine
import com.sentinelnet.engine.api.PlannedMessagingEngine
import com.sentinelnet.engine.api.PlannedNfcEngine
import com.sentinelnet.engine.api.PlannedServerEngine
import com.sentinelnet.engine.api.PlannedWifiDirectEngine
import com.sentinelnet.engine.api.AutomationEngine
import com.sentinelnet.engine.api.DeviceManagerEngine
import com.sentinelnet.engine.api.FirewallEngine
import com.sentinelnet.engine.api.MessagingEngine
import com.sentinelnet.engine.api.NfcEngine
import com.sentinelnet.engine.api.SecurityAuditEngine
import com.sentinelnet.engine.api.ServerEngine
import com.sentinelnet.engine.api.WifiDirectEngine
import com.sentinelnet.engine.api.WifiEngine
import com.sentinelnet.engine.audit.SecurityAuditEngineImpl
import com.sentinelnet.engine.capture.VpnCaptureEngine
import com.sentinelnet.engine.scanner.AndroidDeviceDiscovery
import com.sentinelnet.engine.scanner.NetworkToolsEngineImpl
import com.sentinelnet.engine.scanner.TcpConnectScanner
import com.sentinelnet.engine.wifi.AndroidWifiEngine
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** Implemented engines are bound here; the UI only ever sees the stable interface. */
@Module
@InstallIn(SingletonComponent::class)
abstract class EngineBindings {
    @Binds @Singleton abstract fun wifi(impl: AndroidWifiEngine): WifiEngine
    @Binds @Singleton abstract fun portScan(impl: TcpConnectScanner): PortScanEngine
    @Binds @Singleton abstract fun discovery(impl: AndroidDeviceDiscovery): DeviceDiscoveryEngine
    @Binds @Singleton abstract fun capture(impl: VpnCaptureEngine): CaptureEngine
    @Binds @Singleton abstract fun audit(impl: SecurityAuditEngineImpl): SecurityAuditEngine
    @Binds @Singleton abstract fun netTools(impl: NetworkToolsEngineImpl): NetworkToolsEngine
}

/** Honest placeholders: the UI lists the full roadmap without faking functionality. */
@Module
@InstallIn(SingletonComponent::class)
object PlannedBindings {
    @Provides @Singleton fun ble(): BleEngine = PlannedBleEngine()
    @Provides @Singleton fun nfc(): NfcEngine = PlannedNfcEngine()
    @Provides @Singleton fun cellular(): CellularEngine = PlannedCellularEngine()
    @Provides @Singleton fun p2p(): WifiDirectEngine = PlannedWifiDirectEngine()
    @Provides @Singleton fun ethernet(): EthernetEngine = PlannedEthernetEngine()
    @Provides @Singleton fun firewall(): FirewallEngine = PlannedFirewallEngine()
    @Provides @Singleton fun automation(): AutomationEngine = PlannedAutomationEngine()
    @Provides @Singleton fun server(): ServerEngine = PlannedServerEngine()
    @Provides @Singleton fun messaging(): MessagingEngine = PlannedMessagingEngine()
    @Provides @Singleton fun deviceManager(): DeviceManagerEngine = PlannedDeviceManagerEngine()
}
