package com.sentinelnet.core.android.security

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import android.util.Base64
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Hardware-backed key management (ADR-0005).
 *  - A master key in Android Keystore (StrongBox when available) protects
 *    EncryptedSharedPreferences.
 *  - A random 32-byte SQLCipher passphrase is stored there, never in plaintext.
 *  - The passphrase is generated once and never leaves the device.
 */
@Singleton
class KeystoreManager @Inject constructor(@ApplicationContext private val context: Context) {

    private val masterKey: MasterKey by lazy {
        MasterKey.Builder(context, MASTER_KEY_ALIAS)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .setUserAuthenticationRequired(false)
            .build()
    }

    private val prefs: SharedPreferences by lazy {
        EncryptedSharedPreferences.create(
            context, "sentinelnet-secure", masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun databasePassphrase(): ByteArray {
        val existing = prefs.getString(KEY_DB_PASSPHRASE, null)
        if (existing != null) return Base64.decode(existing, Base64.DEFAULT)
        val fresh = ByteArray(32).also { SecureRandom().nextBytes(it) }
        prefs.edit().putString(KEY_DB_PASSPHRASE, Base64.encodeToString(fresh, Base64.DEFAULT)).apply()
        return fresh
    }

    /** Returns a key alias for per-export encryption; StrongBox is preferred. */
    fun createSigningKey(alias: String): SecretKey? {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")

        fun spec(strongBox: Boolean): KeyGenParameterSpec =
            KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(60)
                .apply {
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                        setIsStrongBoxBacked(strongBox)
                    }
                }
                .build()

        return try {
            generator.init(spec(true))
            generator.generateKey()
        } catch (e: Exception) {
            // StrongBoxUnavailableException is API 28+; catching Exception avoids
            // resolving that class on API 26/27. Retry without StrongBox.
            try {
                generator.init(spec(false))
                generator.generateKey()
            } catch (t: Throwable) { null }
        }
    }

    fun hardwareBacked(): Boolean = try {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = ks.getKey(MASTER_KEY_ALIAS, null) as? SecretKey
        if (key == null) {
            false
        } else {
            val factory = java.security.KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            val info = factory.getKeySpec(key, android.security.keystore.KeyInfo::class.java)
            info.isInsideSecureHardware
        }
    } catch (t: Throwable) { false }

    companion object {
        const val MASTER_KEY_ALIAS = "_sentinelnet_master_"
        const val KEY_DB_PASSPHRASE = "db_passphrase"
    }
}
