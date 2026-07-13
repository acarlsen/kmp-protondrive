package dev.carlsen.protondrive.sdk.apiService

import dev.carlsen.protondrive.sdk.SdkEvents
import dev.carlsen.protondrive.sdk.errors.RateLimitedError
import dev.carlsen.protondrive.sdk.testing.FakeHttpClient
import dev.carlsen.protondrive.sdk.testing.FakeJsonResponse
import dev.carlsen.protondrive.sdk.testing.FakeTelemetry
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Ports the intent of client/js/src/internal/apiService/apiService.test.ts:
 * validates DriveAPIService's retry/error-handling behavior against a fake
 * transport, without relying on the transport's own implementation.
 */
class DriveAPIServiceTest {

    @Serializable
    data class Pong(@SerialName("Code") val code: Int, @SerialName("Message") val message: String)

    private fun okBody(message: String) = buildJsonObject {
        put("Code", ErrorCode.OK)
        put("Message", message)
    }

    private fun errorBody(code: Int, message: String) = buildJsonObject {
        put("Code", code)
        put("Error", message)
    }

    private fun newService(httpClient: FakeHttpClient, telemetry: FakeTelemetry = FakeTelemetry()): DriveAPIService {
        return DriveAPIService(
            telemetry = telemetry,
            sdkEvents = SdkEvents(telemetry),
            httpClient = httpClient,
            baseUrl = "https://api.example",
            language = "en",
        )
    }

    @Test
    fun `successful request decodes the response payload`() = runTest {
        val httpClient = FakeHttpClient()
        httpClient.enqueueResponse(FakeJsonResponse(status = 200, body = okBody("pong")))
        val service = newService(httpClient)

        val result = service.get<Pong>("ping")

        assertEquals(Pong(ErrorCode.OK, "pong"), result)
        assertEquals(1, httpClient.jsonRequests.size)
        assertEquals("https://api.example/ping", httpClient.jsonRequests.single().url)
    }

    @Test
    fun `HTTP 429 is retried using the retry-after header and eventually succeeds`() = runTest {
        val httpClient = FakeHttpClient()
        httpClient.enqueueResponse(
            FakeJsonResponse(status = 429, headers = mapOf("retry-after" to "1"), body = errorBody(0, "slow down")),
        )
        httpClient.enqueueResponse(FakeJsonResponse(status = 200, body = okBody("pong")))
        val service = newService(httpClient)

        val result = service.get<Pong>("ping")

        assertEquals(Pong(ErrorCode.OK, "pong"), result)
        assertEquals(2, httpClient.jsonRequests.size)
    }

    @Test
    fun `an application error code maps to the matching typed error`() = runTest {
        val httpClient = FakeHttpClient()
        httpClient.enqueueResponse(FakeJsonResponse(status = 200, body = errorBody(
            ErrorCode.NOT_EXISTS, "no such node")))
        val service = newService(httpClient)

        val error = assertFailsWith<NotFoundAPIError> { service.get<Pong>("nodes/missing") }
        assertEquals("no such node", error.message)
    }

    @Test
    fun `a transport exception on the first attempt is retried once and can still succeed`() = runTest {
        val httpClient = FakeHttpClient()
        httpClient.enqueueThrow(RuntimeException("boom"))
        httpClient.enqueueResponse(FakeJsonResponse(status = 200, body = okBody("pong")))
        val service = newService(httpClient)

        val result = service.get<Pong>("ping")

        assertEquals(Pong(ErrorCode.OK, "pong"), result)
        assertEquals(2, httpClient.jsonRequests.size)
    }

    @Test
    fun `a 5xx is retried once and then throws if it keeps failing`() = runTest {
        val httpClient = FakeHttpClient()
        httpClient.enqueueResponse(FakeJsonResponse(status = 500, body = errorBody(0, "db down")))
        httpClient.enqueueResponse(FakeJsonResponse(status = 500, body = errorBody(0, "db down")))
        val service = newService(httpClient)

        val error = assertFailsWith<APICodeError> { service.get<Pong>("ping") }
        assertEquals("db down", error.message)
        assertEquals(2, httpClient.jsonRequests.size)
    }

    @Test
    fun `sustained 429s eventually trip the rate-limit circuit breaker`() = runTest {
        val httpClient = FakeHttpClient()
        // 50 subsequent 429s trip the breaker (TOO_MANY_SUBSEQUENT_429_ERRORS); the
        // 51st call should fail fast as a RateLimitedError without a real request.
        repeat(50) {
            httpClient.enqueueResponse(
                FakeJsonResponse(status = 429, headers = mapOf("retry-after" to "0"), body = errorBody(0, "slow down")),
            )
        }
        val service = newService(httpClient)

        assertFailsWith<RateLimitedError> { service.get<Pong>("ping") }
    }
}
