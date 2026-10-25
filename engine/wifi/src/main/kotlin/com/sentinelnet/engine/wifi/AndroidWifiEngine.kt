package com.sentinelnet.engine.wifi

import android.Manifest
import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat
import com.sentinelnet.core.consent.Capability
import com.sentinelnet.core.consent.ConsentGate
import com.sentinelnet.core.consent.ConsentRequests
import com.sentinelnet.core.consent.ConsentResult
import com.sentinelnet.core.domain.ChannelAdvisor
import com.sentinelnet.core.domain.OuiLookup
import com.sentinelnet.core.model.Band
import com.sentinelnet.core.model.ChannelRecommendation
import com.sentinelnet.core.model.WifiNetwork
import com.sentinelnet.core.model.WifiSecurity
import com.sentinelnet.core.model.WifiStandard
import com.sentinelnet.engine.api.EngineStatus
import com.sentinelnet.engine.api.WifiEngine
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Passive Wi-Fi analysis. Uses WifiManager scan results only — no monitor mode,
 * no frame injection, no deauthentication. Android throttles startScan() to
 * ~4 calls/2 min on modern releases; the UI must respect that (battery rule).
 */
@Singleton
class AndroidWifiEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val consentGate: ConsentGate,
    private val channelAdvisor: ChannelAdvisor,
    private val ouiLookup: OuiLookup
) : WifiEngine {

    override val id = "wifi"
    override val displayName = "Wi-Fi analysis"
    override val requiredCapability = Capability.WIFI_SCAN

    private val wifiManager: WifiManager? =
        context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    private val _networks = MutableStateFlow<List<WifiNetwork>>(emptyList())

    override fun status(): EngineStatus = when {
        wifiManager == null -> EngineStatus(false, com.sentinelnet.engine.api.Requirement.HARDWARE, "No Wi-Fi hardware")
        !hasLocationPermission() -> EngineStatus.permission("ACCESS_FINE_LOCATION (Wi-Fi scan requires location on Android 8+)")
        !wifiManager.isWifiEnabled -> EngineStatus(false, com.sentinelnet.engine.api.Requirement.HARDWARE, "Wi-Fi is disabled")
        else -> EngineStatus.ok()
    }

    private fun hasLocationPermission(): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED

    @SuppressLint("MissingPermission")
    override suspend fun scan(): Result<List<WifiNetwork>> = withContext(Dispatchers.IO) {
        if (!hasLocationPermission() || wifiManager == null) {
            return@withContext Result.failure(SecurityException(status().detail))
        }
        val request = ConsentRequests.passive(Capability.WIFI_SCAN)
        val result = consentGate.observe(request) {
            @Suppress("DEPRECATION")
            wifiManager.startScan()
            @Suppress("DEPRECATION")
            val raw: List<ScanResult> = wifiManager.scanResults.orEmpty()
            raw.map(::toModel).also { _networks.value = it }
        }
        when (result) {
            is ConsentResult.Allowed -> Result.success(result.value)
            is ConsentResult.Denied -> Result.failure(SecurityException(result.reason.name))
        }
    }

    override fun observeNetworks(): Flow<List<WifiNetwork>> = callbackFlow {
        trySend(_networks.value)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                if (intent.action == WifiManager.SCAN_RESULTS_AVAILABLE_ACTION && hasLocationPermission()) {
                    launch {
                        @Suppress("DEPRECATION")
                        val models = wifiManager?.scanResults.orEmpty().map(::toModel)
                        _networks.value = models
                        trySend(models)
                    }
                }
            }
        }
        androidx.core.content.ContextCompat.registerReceiver(
            context, receiver, IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION),
            androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED
        )
        awaitClose { context.unregisterReceiver(receiver) }
    }

    private fun toModel(r: ScanResult): WifiNetwork {
        val caps = r.capabilities.orEmpty()
        val security = parseSecurity(caps)
        val ssid = r.SSID?.takeIf { it.isNotBlank() } ?: "<hidden>"
        return WifiNetwork(
            ssid = ssid,
            bssid = r.BSSID.orEmpty(),
            rssiDbm = r.level,
            frequencyMhz = r.frequency,
            channelWidthMhz = inferChannelWidth(r),
            security = security,
            standard = inferStandard(r.frequency),
            wpsEnabled = WifiCapabilitiesParser.hasWps(caps),
            isHidden = r.SSID.isNullOrEmpty(),
            vendor = ouiLookup.lookup(r.BSSID.orEmpty()),
            timestampMillis = System.currentTimeMillis()
        )
    }

    /** ScanResult does not expose PHY rate on all API levels; conservative inference. */
    private fun inferChannelWidth(r: ScanResult): Int = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        when (r.channelWidth) {
            ScanResult.CHANNEL_WIDTH_40MHZ -> 40
            ScanResult.CHANNEL_WIDTH_80MHZ -> 80
            ScanResult.CHANNEL_WIDTH_160MHZ -> 160
            ScanResult.CHANNEL_WIDTH_80MHZ_PLUS_MHZ -> 80
            else -> 20
        }
    } else 20

    private fun inferStandard(freq: Int): WifiStandard = when {
        freq >= 5900 -> WifiStandard.WIFI_6E
        freq >= 5000 -> WifiStandard.WIFI_5
        else -> WifiStandard.WIFI_4
    }

    /** Delegated to a pure parser so it can be unit-tested without Android. */
    internal fun parseSecurity(caps: String): WifiSecurity = WifiCapabilitiesParser.parse(caps)

    override fun recommendChannel(band: Band): ChannelRecommendation =
        channelAdvisor.recommend(band, _networks.value)

    override suspend fun captivePortalCheck(): Boolean = withContext(Dispatchers.IO) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return@withContext false
        val network = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) cm.activeNetwork else null
            ?: return@withContext false
        val caps = cm.getNetworkCapabilities(network) ?: return@withContext false
        !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
    }
}
