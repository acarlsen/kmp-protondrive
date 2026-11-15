package dev.carlsen.protondrive.sdk.apiService

import dev.carlsen.protondrive.sdk.crypto.ServerClock
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

class KtorProtonDriveHttpClientTest {

    private suspend fun captureRequest(userAgent: String?): HttpRequestData {
        lateinit var captured: HttpRequestData
        val engine = MockEngine { request ->
            captured = request
            respond("{}")
        }
        val http = KtorProtonDriveHttpClient(
            appVersion = "external-drive-test@1.2.3",
            userAgent = userAgent,
            sessionProvider = { null },
            client = HttpClient(engine) { install(HttpTimeout) },
        )
        http.fetchJson(ProtonDriveHttpJsonRequest(url = "https://example.test/x", method = "GET", headers = emptyMap(), timeoutMs = 1000))
        return captured
    }

    @Test
    fun sendsAppVersionAndUserAgent() = runTest {
        val request = captureRequest("TestAgent/1.0")
        assertEquals("external-drive-test@1.2.3", request.headers["x-pm-appversion"])
        assertEquals("TestAgent/1.0", request.headers["User-Agent"])
    }

    @Test
    fun omitsUserAgentWhenUnset() = runTest {
        assertNull(captureRequest(null).headers["User-Agent"])
    }

    @Test
    fun updatesServerClockFromResponseHeader() = runTest {
        val serverClock = ServerClock()
        val engine = MockEngine {
            respond("{}", HttpStatusCode.OK, headersOf("x-pm-date", "Sun, 01 Jan 2040 00:00:00 GMT"))
        }
        val http = KtorProtonDriveHttpClient(
            appVersion = "external-drive-test@1.2.3",
            sessionProvider = { null },
            client = HttpClient(engine) { install(HttpTimeout) },
            serverClock = serverClock,
        )
        http.fetchJson(ProtonDriveHttpJsonRequest(url = "https://example.test/x", method = "GET", headers = emptyMap(), timeoutMs = 1000))

        // Offset was captured a moment before now(), so allow a little elapsed time.
        val drift = serverClock.now() - Instant.parse("2040-01-01T00:00:00Z")
        assertTrue(drift.inWholeSeconds in 0..5, "server clock not synced, drift=$drift")
    }
}
