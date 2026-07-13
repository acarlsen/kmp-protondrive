package dev.carlsen.protondrive.sdk.apiService

import dev.carlsen.protondrive.sdk.ApiRetrySucceededEvent
import dev.carlsen.protondrive.sdk.Logger
import dev.carlsen.protondrive.sdk.ProtonDriveTelemetry
import dev.carlsen.protondrive.sdk.SdkEvents
import dev.carlsen.protondrive.sdk.errors.AbortError
import dev.carlsen.protondrive.sdk.errors.ConnectionError
import dev.carlsen.protondrive.sdk.errors.ProtonDriveError
import dev.carlsen.protondrive.sdk.errors.RateLimitedError
import dev.carlsen.protondrive.sdk.errors.ServerError
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/** Thrown by a [ProtonDriveHttpClient] implementation when a request times out. */
class HttpTimeoutError(message: String = "Request timed out") : Exception(message)

/**
 * Thrown by a [ProtonDriveHttpClient] implementation for a transient network
 * failure (e.g. connection reset). Unlike client/js/src/internal/errors.ts
 * isNetworkError(), which sniffs opaque browser/Node fetch error messages,
 * Kotlin http client implementations are expected to throw this type directly
 * since we control the transport contract.
 */
class HttpNetworkError(message: String = "Network error") : Exception(message)

private const val DEFAULT_TIMEOUT_MS = 30_000L
private const val DEFAULT_STORAGE_TIMEOUT_MS = 600_000L

private const val MAX_TIMEOUT_ERROR_RETRY_ATTEMPTS = 3
private const val MAX_NETWORK_ERROR_RETRY_ATTEMPTS = 3

private const val TOO_MANY_SUBSEQUENT_429_ERRORS = 50
private const val TOO_MANY_SUBSEQUENT_429_ERRORS_TIMEOUT_SECONDS = 60

private const val TOO_MANY_SUBSEQUENT_SERVER_ERRORS = 10
private const val TOO_MANY_SUBSEQUENT_SERVER_ERRORS_TIMEOUT_SECONDS = 60

private const val TOO_MANY_SUBSEQUENT_OFFLINE_ERRORS = 10

private const val SERVER_ERROR_RETRY_DELAY_SECONDS = 1
private const val NETWORK_ERROR_RETRY_DELAY_SECONDS = 5
private const val OFFLINE_RETRY_DELAY_SECONDS = 5
private const val DEFAULT_429_RETRY_DELAY_SECONDS = 10
private const val GENERAL_RETRY_DELAY_SECONDS = 1

/**
 * Provides API communication used within the Drive SDK (ports
 * internal/apiService/apiService.ts DriveAPIService).
 *
 * Responsible for headers, error conversion, rate limiting and basic retries.
 * Does not perform authentication itself - the [ProtonDriveHttpClient] the
 * host supplies is expected to already be session-authenticated.
 */
class DriveAPIService(
    private val telemetry: ProtonDriveTelemetry,
    private val sdkEvents: SdkEvents,
    private val httpClient: ProtonDriveHttpClient,
    private val baseUrl: String,
    private val language: String,
    private val sdkVersion: String = "0.1.0",
    @PublishedApi internal val json: Json = Json { ignoreUnknownKeys = true },
) {
    private val logger: Logger = telemetry.getLogger("api")

    private var subsequentTooManyRequestsCounter = 0
    private var lastTooManyRequestsErrorAt: TimeSource.Monotonic.ValueTimeMark? = null

    private var subsequentServerErrorsCounter = 0
    private var lastServerErrorAt: TimeSource.Monotonic.ValueTimeMark? = null

    private var subsequentOfflineErrorsCounter = 0

    suspend inline fun <reified ResponsePayload> get(url: String, priority: String = "u=4"): ResponsePayload =
        decode(requestJson(url, "GET", null, priority))

    suspend inline fun <reified RequestPayload, reified ResponsePayload> post(
        url: String,
        data: RequestPayload? = null,
        priority: String = "u=4",
    ): ResponsePayload = decode(requestJson(url, "POST", data?.let { json.encodeToJsonElement(it) }, priority))

    suspend inline fun <reified RequestPayload, reified ResponsePayload> put(
        url: String,
        data: RequestPayload,
        priority: String = "u=4",
    ): ResponsePayload = decode(requestJson(url, "PUT", json.encodeToJsonElement(data), priority))

    suspend inline fun <reified RequestPayload, reified ResponsePayload> delete(
        url: String,
        data: RequestPayload? = null,
        priority: String = "u=4",
    ): ResponsePayload = decode(requestJson(url, "DELETE", data?.let { json.encodeToJsonElement(it) }, priority))

    /** Decodes with the raw JSON attached to the exception on failure - a shape mismatch is much faster to fix when you can see what actually came back. */
    @PublishedApi
    internal inline fun <reified ResponsePayload> decode(element: JsonElement): ResponsePayload = try {
        json.decodeFromJsonElement(element)
    } catch (e: kotlinx.serialization.SerializationException) {
        throw ProtonDriveError(
            "Failed to decode response as ${ResponsePayload::class.simpleName}: ${e.message}\nRaw response: $element",
            e,
        )
    }

    /** Core JSON request path; all typed get/post/put/delete helpers funnel through here. */
    suspend fun requestJson(url: String, method: String, body: JsonElement?, priority: String = "u=4"): JsonElement {
        val headers = buildMap {
            put("Accept", "application/vnd.protonmail.v1+json")
            put("Language", language)
            put("x-pm-drive-sdk-version", "kotlin@$sdkVersion")
            put("Priority", priority)
            if (body != null) put("Content-Type", "application/json")
        }
        val fullUrl = "$baseUrl/$url"
        val request = ProtonDriveHttpJsonRequest(url = fullUrl, method = method, headers = headers, timeoutMs = DEFAULT_TIMEOUT_MS, json = body)

        val response = fetchWithRetry(fullUrl, method) { httpClient.fetchJson(request) }

        val result: JsonElement = try {
            response.json()
        } catch (e: ProtonDriveError) {
            throw e
        } catch (e: Exception) {
            throw apiErrorFactory(status = response.status, statusText = response.statusText, error = e)
        }

        val code = (result as? JsonObject)?.get("Code")?.jsonPrimitive?.intOrNull ?: 0
        if (!response.ok || !isCodeOk(code)) {
            throw apiErrorFactory(status = response.status, statusText = response.statusText, result = result)
        }
        if (isCodeOkAsync(code)) {
            logger.info("$method $fullUrl: deferred action")
        }
        return result
    }

    suspend fun getBlockStream(url: String, token: String, priority: String = "u=4"): ByteArray =
        makeStorageRequest("GET", url, token, null, null, null, priority).bodyBytes()

    /** [contentType], when given, is sent as-is (e.g. "multipart/form-data; boundary=...") - block upload requires multipart, unlike every other JSON/octet-stream request this SDK makes. */
    suspend fun postBlockStream(
        url: String,
        token: String,
        data: ByteArray,
        contentType: String? = null,
        onProgress: ((uploadedBytes: Long) -> Unit)? = null,
        priority: String = "u=4",
    ) {
        makeStorageRequest("POST", url, token, data, onProgress, contentType, priority)
    }

    private suspend fun makeStorageRequest(
        method: String,
        url: String,
        token: String,
        body: ByteArray?,
        onProgress: ((uploadedBytes: Long) -> Unit)?,
        contentType: String? = null,
        priority: String = "u=4",
    ): ProtonDriveHttpResponse {
        val headers = buildMap {
            put("pm-storage-token", token)
            put("Language", language)
            put("x-pm-drive-sdk-version", "kotlin@$sdkVersion")
            put("Priority", priority)
            if (contentType != null) put("Content-Type", contentType)
        }
        val request = ProtonDriveHttpBlobRequest(
            url = url,
            method = method,
            headers = headers,
            timeoutMs = DEFAULT_STORAGE_TIMEOUT_MS,
            body = body,
            onProgress = onProgress,
        )

        val response = fetchWithRetry(url, method) { httpClient.fetchBlob(request) }

        if (response.status >= 400) {
            val result = try {
                response.json()
            } catch (e: ProtonDriveError) {
                throw e
            } catch (e: Exception) {
                throw apiErrorFactory(status = response.status, statusText = response.statusText, error = e)
            }
            throw apiErrorFactory(status = response.status, statusText = response.statusText, result = result)
        }
        return response
    }

    private suspend fun fetchWithRetry(
        url: String,
        method: String,
        attempt: Int = 0,
        previousError: Any? = null,
        callback: suspend () -> ProtonDriveHttpResponse,
    ): ProtonDriveHttpResponse {
        if (attempt > 0) logger.debug("$method $url: retry $attempt") else logger.debug("$method $url")

        if (hasReachedServerErrorLimit()) {
            logger.warn("Server errors limit reached")
            throw ServerError("Too many server errors, please try again later")
        }
        if (hasReachedTooManyRequestsErrorLimit()) {
            logger.warn("Too many requests limit reached")
            throw RateLimitedError("Too many server requests, please try again later")
        }

        val start = TimeSource.Monotonic.markNow()

        val response: ProtonDriveHttpResponse
        try {
            response = callback()
        } catch (e: CancellationException) {
            throw e
        } catch (e: AbortError) {
            logger.debug("$method $url: Aborted")
            throw e
        } catch (e: ConnectionError) {
            offlineErrorHappened()
            logger.info("$method $url: Offline error, retrying")
            delay(OFFLINE_RETRY_DELAY_SECONDS.seconds)
            return fetchWithRetry(url, method, attempt + 1, e, callback)
        } catch (e: HttpTimeoutError) {
            if (attempt + 1 < MAX_TIMEOUT_ERROR_RETRY_ATTEMPTS) {
                logger.warn("$method $url: Timeout error, retrying")
                delay(SERVER_ERROR_RETRY_DELAY_SECONDS.seconds)
                return fetchWithRetry(url, method, attempt + 1, e, callback)
            }
            return retryOnceOrThrow(url, method, attempt, e, callback)
        } catch (e: HttpNetworkError) {
            if (attempt + 1 < MAX_NETWORK_ERROR_RETRY_ATTEMPTS) {
                logger.warn("$method $url: Network error, retrying")
                delay(NETWORK_ERROR_RETRY_DELAY_SECONDS.seconds)
                return fetchWithRetry(url, method, attempt + 1, e, callback)
            }
            return retryOnceOrThrow(url, method, attempt, e, callback)
        } catch (e: Exception) {
            return retryOnceOrThrow(url, method, attempt, e, callback)
        }

        clearSubsequentOfflineErrors()

        val durationMs = start.elapsedNow().inWholeMilliseconds
        if (response.ok) {
            logger.info("$method $url: ${response.status} (${durationMs}ms)")
        } else {
            logger.warn("$method $url: ${response.status} (${durationMs}ms)")
        }

        if (response.status == HTTPErrorCode.TOO_MANY_REQUESTS) {
            tooManyRequestsErrorHappened()
            val retryAfter = response.headers["retry-after"]?.toIntOrNull() ?: DEFAULT_429_RETRY_DELAY_SECONDS
            delay(retryAfter.seconds)
            return fetchWithRetry(url, method, attempt + 1, response.status, callback)
        } else {
            clearSubsequentTooManyRequestsError()
        }

        // Automatically re-try 5xx glitches on the server, but only once, and
        // report the incident so it can be followed up.
        if (response.status >= 500) {
            serverErrorHappened()
            if (attempt > 0) {
                logger.warn("$method $url: ${response.status} - retry failed")
            } else {
                delay(SERVER_ERROR_RETRY_DELAY_SECONDS.seconds)
                return fetchWithRetry(url, method, attempt + 1, response.status, callback)
            }
        } else {
            if (attempt > 0) {
                val previousErrorMessage = (previousError as? Throwable)?.message ?: previousError?.toString()
                val isWarning = previousError !is Throwable ||
                    (previousError !is HttpTimeoutError && previousError !is ConnectionError && previousError !is HttpNetworkError)

                if (isWarning) {
                    telemetry.recordMetric(
                        ApiRetrySucceededEvent(failedAttempts = attempt, url = url, previousError = previousErrorMessage),
                    )
                    logger.warn("$method $url: $previousErrorMessage - retry helped")
                } else {
                    logger.debug("$method $url: $previousErrorMessage - retry helped")
                }
            }
            clearSubsequentServerErrors()
        }

        return response
    }

    /** Retries once unconditionally on the first attempt, mirroring the TS "catch-all" retry branch. */
    private suspend fun retryOnceOrThrow(
        url: String,
        method: String,
        attempt: Int,
        error: Exception,
        callback: suspend () -> ProtonDriveHttpResponse,
    ): ProtonDriveHttpResponse {
        if (attempt == 0) {
            logger.error("$method $url: failed, retrying once", error)
            delay(GENERAL_RETRY_DELAY_SECONDS.seconds)
            return fetchWithRetry(url, method, 1, error, callback)
        }
        logger.error("$method $url: failed", error)
        throw error
    }

    private fun hasReachedTooManyRequestsErrorLimit(): Boolean {
        val last = lastTooManyRequestsErrorAt ?: return false
        val secondsSinceLast = last.elapsedNow().inWholeSeconds
        return subsequentTooManyRequestsCounter >= TOO_MANY_SUBSEQUENT_429_ERRORS &&
            secondsSinceLast < TOO_MANY_SUBSEQUENT_429_ERRORS_TIMEOUT_SECONDS
    }

    private fun tooManyRequestsErrorHappened() {
        subsequentTooManyRequestsCounter++
        lastTooManyRequestsErrorAt = TimeSource.Monotonic.markNow()

        // Don't emit the event for the first few 429s, only when the client is
        // very limited. This is a generic event; it doesn't account for
        // per-endpoint rate limits.
        if (subsequentTooManyRequestsCounter == TOO_MANY_SUBSEQUENT_429_ERRORS) {
            sdkEvents.requestsThrottled()
        }
    }

    private fun clearSubsequentTooManyRequestsError() {
        if (subsequentTooManyRequestsCounter >= TOO_MANY_SUBSEQUENT_429_ERRORS) {
            sdkEvents.requestsUnthrottled()
        }
        subsequentTooManyRequestsCounter = 0
        lastTooManyRequestsErrorAt = null
    }

    private fun hasReachedServerErrorLimit(): Boolean {
        val last = lastServerErrorAt ?: return false
        val secondsSinceLast = last.elapsedNow().inWholeSeconds
        return subsequentServerErrorsCounter >= TOO_MANY_SUBSEQUENT_SERVER_ERRORS &&
            secondsSinceLast < TOO_MANY_SUBSEQUENT_SERVER_ERRORS_TIMEOUT_SECONDS
    }

    private fun serverErrorHappened() {
        subsequentServerErrorsCounter++
        lastServerErrorAt = TimeSource.Monotonic.markNow()
    }

    private fun clearSubsequentServerErrors() {
        subsequentServerErrorsCounter = 0
        lastServerErrorAt = null
    }

    private fun offlineErrorHappened() {
        subsequentOfflineErrorsCounter++
        if (subsequentOfflineErrorsCounter == TOO_MANY_SUBSEQUENT_OFFLINE_ERRORS) {
            sdkEvents.transfersPaused()
        }
    }

    private fun clearSubsequentOfflineErrors() {
        if (subsequentOfflineErrorsCounter >= TOO_MANY_SUBSEQUENT_OFFLINE_ERRORS) {
            sdkEvents.transfersResumed()
        }
        subsequentOfflineErrorsCounter = 0
    }
}
