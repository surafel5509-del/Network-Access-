package com.sentinelnet.app

import android.app.Application
import com.sentinelnet.core.android.di.ConsentRepository
import com.sentinelnet.core.consent.ConsentGate
import dagger.hilt.android.HiltAndroidApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltAndroidApp
class SentinelNetApp : Application() {

    @Inject lateinit var consentGate: ConsentGate
    @Inject lateinit var consentRepository: ConsentRepository

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    init {
        // Native SQLCipher must be loaded before Room opens the encrypted DB.
        try { System.loadLibrary("sqlcipher") } catch (t: Throwable) {
            android.util.Log.w("SentinelNet", "SQLCipher native library unavailable", t)
        }
    }

    override fun onCreate() {
        super.onCreate()
        // The gate starts fail-closed; keep it synchronised with persisted settings.
        appScope.launch {
            consentRepository.policyFlow.collect { policy -> consentGate.updatePolicy(policy) }
        }
    }
}
