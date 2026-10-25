package com.sentinelnet.core.android.di

import android.content.Context
import androidx.room.Room
import com.sentinelnet.core.android.data.RoomAuditLog
import com.sentinelnet.core.android.data.SentinelDatabase
import com.sentinelnet.core.android.security.KeystoreManager
import com.sentinelnet.core.consent.AuditLog
import com.sentinelnet.core.consent.Clock
import com.sentinelnet.core.consent.ConsentGate
import com.sentinelnet.core.consent.SystemClock
import com.sentinelnet.core.domain.ChannelAdvisor
import com.sentinelnet.core.domain.CveHintMatcher
import com.sentinelnet.core.domain.OuiLookup
import com.sentinelnet.core.domain.WifiSecurityAuditor
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit
import javax.inject.Qualifier
import javax.inject.Singleton

@Qualifier annotation class IoDispatcher
@Qualifier annotation class DefaultDispatcher

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides @Singleton
    fun provideClock(): Clock = SystemClock

    @Provides @Singleton
    fun provideOuiLookup(): OuiLookup = OuiLookup()

    @Provides @Singleton
    fun provideChannelAdvisor(oui: OuiLookup): ChannelAdvisor = ChannelAdvisor(oui)

    @Provides @Singleton
    fun provideWifiAuditor(oui: OuiLookup): WifiSecurityAuditor = WifiSecurityAuditor(oui)

    @Provides @Singleton
    fun provideCveHintMatcher(): CveHintMatcher = CveHintMatcher()

    @Provides @Singleton
    fun provideDatabase(
        @ApplicationContext context: Context,
        keystore: KeystoreManager
    ): SentinelDatabase {
        try { System.loadLibrary("sqlcipher") } catch (t: Throwable) { /* logged by the caller */ }
        // SQLCipher 4.5.5 (`net.zetetic:sqlcipher-android`) uses
        // SupportOpenHelperFactory; the native lib is loaded in SentinelNetApp.
        // The 32-byte passphrase lives in Keystore-protected prefs.
        val factory = SupportOpenHelperFactory(keystore.databasePassphrase())
        return Room.databaseBuilder(context, SentinelDatabase::class.java, "sentinelnet.db")
            .openHelperFactory(factory)
            .fallbackToDestructiveMigration()
            .build()
    }

    @Provides @Singleton
    fun provideAuditLog(db: SentinelDatabase, clock: Clock): AuditLog =
        RoomAuditLog(db.auditDao(), clock)

    @Provides @Singleton
    fun provideConsentGate(auditLog: AuditLog, clock: Clock): ConsentGate {
        // Fail-closed default. SentinelNetApp updates the policy from DataStore
        // immediately on process start; until then every action is denied.
        return ConsentGate(auditLog = auditLog, clock = clock)
    }

    @Provides @Singleton
    fun provideOkHttpClient(): OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .followRedirects(true)
        // Certificate pinning for opt-in online services is enabled in release
        // builds with real SPKI hashes from BuildConfig (see docs/DEVELOPER_GUIDE.md).
        // A placeholder pin would silently break RDAP, so none is shipped here.
        .build()

    @Provides @IoDispatcher fun provideIoDispatcher(): CoroutineDispatcher = Dispatchers.IO
    @Provides @DefaultDispatcher fun provideDefaultDispatcher(): CoroutineDispatcher = Dispatchers.Default
}
