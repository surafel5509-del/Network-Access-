package com.sentinelnet.core.android.data

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase
import com.sentinelnet.core.consent.AuditLog
import com.sentinelnet.core.consent.Clock
import com.sentinelnet.core.model.AuditEvent
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "audit_events")
data class AuditEventEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val sequence: Long,
    val timestampMillis: Long,
    val actor: String,
    val capability: String,
    val target: String,
    val decision: String,
    val reason: String,
    val sessionId: String
)

@Entity(tableName = "score_history")
data class ScoreHistoryEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val overall: Int,
    val fingerprint: String,
    val computedAtMillis: Long
)

@Entity(tableName = "saved_networks")
data class SavedNetworkEntity(
    @PrimaryKey val bssid: String,
    val ssid: String,
    val security: String,
    val lastRssiDbm: Int,
    val firstSeenMillis: Long,
    val lastSeenMillis: Long
)

@Dao
interface AuditDao {
    // Synchronous by design: callers are always on Dispatchers.IO. SQLCipher
    // encryption is transparent, so these remain fast for the append-only log.
    @Insert(onConflict = OnConflictStrategy.ABORT)
    fun insert(event: AuditEventEntity)

    @Query("SELECT * FROM audit_events ORDER BY sequence ASC")
    fun all(): List<AuditEventEntity>

    @Query("SELECT * FROM audit_events WHERE sessionId = :sessionId ORDER BY sequence ASC")
    fun forSession(sessionId: String): List<AuditEventEntity>

    @Query("SELECT * FROM audit_events ORDER BY sequence DESC LIMIT :limit")
    fun observe(limit: Int): Flow<List<AuditEventEntity>>

    @Query("SELECT COUNT(*) FROM audit_events")
    fun count(): Int

    @Query("DELETE FROM audit_events")
    fun clear()
}

@Dao
interface ScoreDao {
    @Insert
    fun insert(entry: ScoreHistoryEntity)

    @Query("SELECT * FROM score_history ORDER BY computedAtMillis DESC LIMIT :limit")
    fun history(limit: Int): Flow<List<ScoreHistoryEntity>>
}

@Dao
interface NetworkDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun upsert(network: SavedNetworkEntity)

    @Query("SELECT * FROM saved_networks ORDER BY lastSeenMillis DESC")
    fun all(): Flow<List<SavedNetworkEntity>>
}

@Database(
    entities = [AuditEventEntity::class, ScoreHistoryEntity::class, SavedNetworkEntity::class],
    version = 1,
    exportSchema = true
)
abstract class SentinelDatabase : RoomDatabase() {
    abstract fun auditDao(): AuditDao
    abstract fun scoreDao(): ScoreDao
    abstract fun networkDao(): NetworkDao
}

/** SQLCipher-backed AuditLog. Every append is durable before the guarded action starts. */
class RoomAuditLog(
    private val dao: AuditDao,
    private val clock: Clock
) : AuditLog {
    override fun append(event: AuditEvent) {
        dao.insert(
            AuditEventEntity(
                sequence = event.sequence, timestampMillis = event.timestampMillis,
                actor = event.actor, capability = event.capability, target = event.target,
                decision = event.decision, reason = event.reason, sessionId = event.sessionId
            )
        )
    }

    override fun all(): List<AuditEvent> = dao.all().map { it.toModel() }

    override fun forSession(sessionId: String): List<AuditEvent> = dao.forSession(sessionId).map { it.toModel() }

    override fun size(): Int = dao.count()

    override fun clear() = dao.clear()

    fun record(
        actor: String, capability: String, target: String,
        decision: String, reason: String, sessionId: String
    ): AuditEvent {
        val event = AuditEvent(
            sequence = size() + 1L, timestampMillis = clock.nowMillis(),
            actor = actor, capability = capability, target = target,
            decision = decision, reason = reason, sessionId = sessionId
        )
        append(event)
        return event
    }

    private fun AuditEventEntity.toModel() = AuditEvent(
        sequence, timestampMillis, actor, capability, target, decision, reason, sessionId
    )
}
