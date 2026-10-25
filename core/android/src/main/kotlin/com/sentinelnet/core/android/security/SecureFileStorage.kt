package com.sentinelnet.core.android.security

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/** EncryptedFile-backed storage for pcap, PDF/JSON reports and HAR exports. */
@Singleton
class SecureFileStorage @Inject constructor(@ApplicationContext private val context: Context) {

    private val masterKey by lazy {
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }

    fun create(name: String): EncryptedFile {
        val dir = File(context.filesDir, "exports").also { it.mkdirs() }
        val file = File(dir, name)
        if (file.exists()) file.delete()
        return EncryptedFile.Builder(
            context, file, masterKey, EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()
    }

    fun listExports(): List<File> =
        File(context.filesDir, "exports").listFiles()?.toList().orEmpty()

    fun deleteAllExports() { listExports().forEach { it.delete() } }
}
