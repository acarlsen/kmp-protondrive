package dev.carlsen.protondrive.sdk.apiService

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.HttpRequestData
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

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
}
