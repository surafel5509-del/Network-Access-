package com.sentinelnet.core.reporting

/**
 * A tiny, dependency-free JSON writer. :core:pure must compile on a plain JDK
 * without kotlinx.serialization, and reports must be byte-for-byte reproducible
 * (stable field order, no reflection) for the chain-of-custody hash in E6.
 */
sealed class JsonValue {
    abstract fun render(level: Int, pretty: Boolean): String
    fun toJson(pretty: Boolean = true): String = render(0, pretty)
}

data class JStr(val value: String) : JsonValue() {
    override fun render(level: Int, pretty: Boolean): String = buildString {
        append('"')
        for (c in value) when {
            c == '"' -> append("\\\"")
            c == '\\' -> append("\\\\")
            c == '\n' -> append("\\n")
            c == '\r' -> append("\\r")
            c == '\t' -> append("\\t")
            c == '\b' -> append("\\b")
            c == '\u000C' -> append("\\f")
            c.code < 0x20 -> append("\\u%04x".format(c.code))
            else -> append(c)
        }
        append('"')
    }
}
data class JNum(val literal: String) : JsonValue() {
    constructor(value: Number) : this(value.toString())
    override fun render(level: Int, pretty: Boolean): String = literal
}
data class JBool(val value: Boolean) : JsonValue() {
    override fun render(level: Int, pretty: Boolean): String = value.toString()
}
object JNull : JsonValue() {
    override fun render(level: Int, pretty: Boolean): String = "null"
}
data class JArr(val values: List<JsonValue>) : JsonValue() {
    override fun render(level: Int, pretty: Boolean): String {
        if (values.isEmpty()) return "[]"
        if (!pretty) return values.joinToString(",", "[", "]") { it.render(level + 1, false) }
        val pad = "  ".repeat(level + 1)
        return values.joinToString(",\n", "[\n", "\n${"  ".repeat(level)}]") {
            pad + it.render(level + 1, true)
        }
    }
}
data class JObj(val fields: LinkedHashMap<String, JsonValue>) : JsonValue() {
    override fun render(level: Int, pretty: Boolean): String {
        if (fields.isEmpty()) return "{}"
        if (!pretty) return fields.entries.joinToString(",", "{", "}") {
            JStr(it.key).render(level + 1, false) + ":" + it.value.render(level + 1, false)
        }
        val pad = "  ".repeat(level + 1)
        return fields.entries.joinToString(",\n", "{\n", "\n${"  ".repeat(level)}}") {
            pad + JStr(it.key).render(level + 1, true) + ": " + it.value.render(level + 1, true)
        }
    }
}

class JsonObjectBuilder {
    private val fields = LinkedHashMap<String, JsonValue>()
    fun put(key: String, value: JsonValue): JsonObjectBuilder { fields[key] = value; return this }
    fun str(key: String, value: String) = put(key, JStr(value))
    fun nullableStr(key: String, value: String?) = put(key, value?.let(::JStr) ?: JNull)
    fun num(key: String, value: Number) = put(key, JNum(value))
    fun bool(key: String, value: Boolean) = put(key, JBool(value))
    fun arr(key: String, values: List<JsonValue>) = put(key, JArr(values))
    fun obj(key: String, block: JsonObjectBuilder.() -> Unit) = put(key, buildJson(block))
    fun strings(key: String, values: Iterable<String>) = arr(key, values.map(::JStr).toList())
    fun build(): JObj = JObj(fields)
}

fun buildJson(block: JsonObjectBuilder.() -> Unit): JObj = JsonObjectBuilder().apply(block).build()

/** Convenience for arrays of objects. */
fun jsonArrayOf(items: Iterable<JsonObjectBuilder.() -> Unit>): JArr =
    JArr(items.map { buildJson(it) })
