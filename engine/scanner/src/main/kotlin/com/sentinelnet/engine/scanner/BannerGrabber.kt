package com.sentinelnet.engine.scanner

import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.Socket
import javax.net.ssl.SSLSocketFactory

/** Passive banner grabbing + TLS certificate metadata. Never sends exploit payloads. */
object BannerGrabber {

    private val SERVICE_NAMES = mapOf(
        21 to "FTP", 22 to "SSH", 23 to "Telnet", 25 to "SMTP", 53 to "DNS", 80 to "HTTP",
        110 to "POP3", 143 to "IMAP", 443 to "HTTPS", 445 to "SMB", 993 to "IMAPS",
        995 to "POP3S", 1433 to "MSSQL", 3306 to "MySQL", 3389 to "RDP", 5432 to "PostgreSQL",
        5900 to "VNC", 6379 to "Redis", 8080 to "HTTP-alt", 8443 to "HTTPS-alt",
        9200 to "Elasticsearch", 27017 to "MongoDB"
    )

    fun serviceFor(port: Int): String? = SERVICE_NAMES[port]

    fun grab(socket: Socket, target: String, port: Int): String? = try {
        when (port) {
            80, 8080, 8000, 8008, 8888 -> httpHead(socket, target)
            else -> readGreeting(socket)
        }
    } catch (t: Throwable) { null }

    private fun httpHead(socket: Socket, target: String): String? {
        socket.getOutputStream().write(
            "HEAD / HTTP/1.1\r\nHost: $target\r\nUser-Agent: SentinelNet/0.1 (authorized audit)\r\nConnection: close\r\n\r\n"
                .toByteArray(Charsets.ISO_8859_1)
        )
        socket.getOutputStream().flush()
        return BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.ISO_8859_1))
            .lineSequence().take(12).joinToString(" | ").take(400)
    }

    private fun readGreeting(socket: Socket): String? {
        val buffer = ByteArray(512)
        val read = socket.getInputStream().read(buffer)
        if (read <= 0) return null
        return String(buffer, 0, read, Charsets.ISO_8859_1)
            .map { if (it.isISOControl()) ' ' else it }
            .joinToString("").trim().take(200).ifBlank { null }
    }

    /** Extracts a version-like token from a banner, for passive CVE hinting. */
    fun versionFrom(banner: String?): String? {
        if (banner == null) return null
        val regex = Regex("""(\d+\.\d+(?:\.\d+)?(?:[-a-zA-Z0-9.]*)?)""")
        return regex.find(banner)?.value
    }

    /** Opens a TLS connection to read the peer certificate (no MITM, no trust bypass). */
    fun tlsSubject(host: String, port: Int, timeoutMs: Int = 1500): String? = try {
        val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
        (factory.createSocket() as javax.net.ssl.SSLSocket).use { ssl ->
            ssl.soTimeout = timeoutMs
            ssl.connect(java.net.InetSocketAddress(host, port), timeoutMs)
            ssl.startHandshake()
            val cert = ssl.session.peerCertificates.firstOrNull() as? java.security.cert.X509Certificate
            cert?.subjectX500Principal?.name
        }
    } catch (t: Throwable) { null }
}
