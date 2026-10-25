package com.sentinelnet.core.android.di

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.sentinelnet.core.consent.ConsentPolicy
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore("sentinelnet_settings")

/** Fail-closed defaults: Safe Mode ON, legal notice NOT accepted, online features OFF. */
@Singleton
class ConsentRepository @Inject constructor(@ApplicationContext private val context: Context) {

    private object Keys {
        val LEGAL_ACCEPTED = booleanPreferencesKey("legal_accepted")
        val NOTICE_VERSION = intPreferencesKey("notice_version")
        val SAFE_MODE = booleanPreferencesKey("safe_mode")
        val ONLINE = booleanPreferencesKey("online_features")
        val BIOMETRIC = booleanPreferencesKey("biometric")
        val HIGH_CONTRAST = booleanPreferencesKey("high_contrast")
        val ONBOARDING_DONE = booleanPreferencesKey("onboarding_done")
    }

    val policyFlow: Flow<ConsentPolicy> = context.dataStore.data.map { p ->
        ConsentPolicy(
            legalNoticeAccepted = p[Keys.LEGAL_ACCEPTED] ?: false,
            acceptedNoticeVersion = p[Keys.NOTICE_VERSION] ?: 0,
            safeMode = p[Keys.SAFE_MODE] ?: true
        )
    }

    suspend fun currentPolicy(): ConsentPolicy = policyFlow.first()

    suspend fun acceptLegalNotice(version: Int) {
        context.dataStore.edit {
            it[Keys.LEGAL_ACCEPTED] = true
            it[Keys.NOTICE_VERSION] = version
            it[Keys.ONBOARDING_DONE] = true
        }
    }

    suspend fun setSafeMode(enabled: Boolean) { context.dataStore.edit { it[Keys.SAFE_MODE] = enabled } }
    suspend fun setOnlineFeatures(enabled: Boolean) { context.dataStore.edit { it[Keys.ONLINE] = enabled } }
    suspend fun setBiometric(enabled: Boolean) { context.dataStore.edit { it[Keys.BIOMETRIC] = enabled } }
    suspend fun setHighContrast(enabled: Boolean) { context.dataStore.edit { it[Keys.HIGH_CONTRAST] = enabled } }

    fun onboardingDone(): Flow<Boolean> = context.dataStore.data.map { it[Keys.ONBOARDING_DONE] ?: false }
    fun onlineFeatures(): Flow<Boolean> = context.dataStore.data.map { it[Keys.ONLINE] ?: false }
    fun highContrast(): Flow<Boolean> = context.dataStore.data.map { it[Keys.HIGH_CONTRAST] ?: false }
    fun biometric(): Flow<Boolean> = context.dataStore.data.map { it[Keys.BIOMETRIC] ?: false }
}
