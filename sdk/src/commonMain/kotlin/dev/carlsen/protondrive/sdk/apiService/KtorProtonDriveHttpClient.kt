package dev.carlsen.protondrive.sdk.apiService

import dev.carlsen.protondrive.sdk.errors.ConnectionError
import io.ktor.client.HttpClient
import io.ktor.client.network.sockets.ConnectTimeoutException
import io.ktor.client.network.sockets.SocketTimeoutException
import io.ktor.client.plugins.HttpRequestTimeoutException
import io.ktor.client.plugins.onUpload
import io.ktor.client.plugins.timeout
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsBytes
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.contentType
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull

/**
 * Real network transport for [ProtonDriveHttpClient], using Ktor's client with a per-platform
 * default engine (see [defaultHttpClient]: OkHttp on Android, CIO on plain JVM - a future
 * iOS/Native target only needs another actual with e.g. the Darwin engine). Attaches
 * session headers via [sessionProvider] - matching this SDK's rule that session storage/refresh
 * belongs to the host app, not the library: call [ProtonAuth][dev.carlsen.protondrive.sdk.auth.ProtonAuth]
 * to obtain a session, then have [sessionProvider] return it (e.g. from a mutable holder the host
 * updates after login/refresh).
 *
 * Maps transport failures to the exception types [DriveAPIService]'s retry logic expects:
 * [HttpTimeoutError], [HttpNetworkError], and (for DNS/connect failures, treated as "offline")
 * [dev.carlsen.protondrive.sdk.errors.ConnectionError].
 */
class KtorProtonDriveHttpClient(
    private val appVersion: String,
    private val sessionProvider: () -> ProtonSession?,
    private val client: HttpClient = defaultHttpClient(),
    private val json: Json = Json { ignoreUnknownKeys = true },
) : ProtonDriveHttpClient {

    override suspend fun fetchJson(request: ProtonDriveHttpJsonRequest): ProtonDriveHttpResponse {
        val bodyJson = request.json
        val bodyBytes = when {
            bodyJson != null -> json.encodeToString(JsonElement.serializer(), bodyJson).encodeToByteArray()
            request.body != null -> request.body
            else -> null
        }
        return execute(request, bodyBytes, JSON_CONTENT_TYPE, onProgress = null)
    }

    override suspend fun fetchBlob(request: ProtonDriveHttpBlobRequest): ProtonDriveHttpResponse {
        // A Content-Type already set via headers (e.g. multipart/form-data for block upload)
        // takes precedence over the default.
        val contentType = request.headers["Content-Type"] ?: OCTET_STREAM_CONTENT_TYPE
        return execute(request, request.body, contentType, request.onProgress)
    }

    private suspend fun execute(
        request: ProtonDriveHttpBaseRequest,
        body: ByteArray?,
        defaultContentType: String,
        onProgress: ((uploadedBytes: Long) -> Unit)?,
    ): ProtonDriveHttpResponse {
        try {
            val response = client.request(request.url) {
                method = HttpMethod.parse(request.method)
                timeout { requestTimeoutMillis = request.timeoutMs }
                request.headers.forEach { (name, value) ->
                    if (!name.equals("Content-Type", ignoreCase = true)) header(name, value)
                }
                header("x-pm-appversion", appVersion)
                sessionProvider()?.let { session ->
                    header("x-pm-uid", session.uid)
                    header("Authorization", "Bearer ${session.accessToken}")
                }
                if (body != null) {
                    contentType(ContentType.parse(defaultContentType))
                    setBody(body)
                }
                if (onProgress != null) {
                    onUpload { bytesSentTotal, _ -> onProgress(bytesSentTotal) }
                }
            }
            return KtorProtonDriveHttpResponse(response, json)
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpRequestTimeoutException) {
            throw HttpTimeoutError(e.message ?: "Request timed out")
        } catch (e: ConnectTimeoutException) {
            throw HttpTimeoutError(e.message ?: "Request timed out")
        } catch (e: SocketTimeoutException) {
            throw HttpTimeoutError(e.message ?: "Request timed out")
        } catch (e: Exception) {
            if (isOfflineError(e)) {
                throw ConnectionError(e.message ?: "No network connection")
            }
            throw HttpNetworkError(e.message ?: "Network error")
        }
    }

    private companion object {
        const val JSON_CONTENT_TYPE = "application/json"
        const val OCTET_STREAM_CONTENT_TYPE = "application/octet-stream"
    }
}

private class KtorProtonDriveHttpResponse(
    private val response: HttpResponse,
    private val json: Json,
) : ProtonDriveHttpResponse {
    override val status: Int = response.status.value
    override val statusText: String = response.status.description
    override val headers: Map<String, String> = response.headers.names().associateWith { name -> response.headers[name] ?: "" }

    override suspend fun json(): JsonElement {
        val text = response.bodyAsBytes().decodeToString()
        if (text.isEmpty()) return JsonNull
        return json.parseToJsonElement(text)
    }

    override suspend fun bodyBytes(): ByteArray = response.bodyAsBytes()
}
