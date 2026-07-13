package dev.carlsen.protondrive.sdk.apiService

import kotlinx.serialization.json.JsonElement

/**
 * Transport the host application must supply (ports interface/httpClient.ts).
 *
 * Like the JS SDK, this SDK does not perform authentication or session
 * management itself - the host app's implementation is expected to attach
 * whatever auth/session headers or cookies a request needs before sending it.
 * See root README.md "Scope and Limitations" in proton-sdk for the rationale.
 */
interface ProtonDriveHttpClient {
    suspend fun fetchJson(request: ProtonDriveHttpJsonRequest): ProtonDriveHttpResponse

    suspend fun fetchBlob(request: ProtonDriveHttpBlobRequest): ProtonDriveHttpResponse
}

data class ProtonDriveHttpJsonRequest(
    override val url: String,
    override val method: String,
    override val headers: Map<String, String>,
    override val timeoutMs: Long,
    val json: JsonElement? = null,
    val body: ByteArray? = null,
) : ProtonDriveHttpBaseRequest

data class ProtonDriveHttpBlobRequest(
    override val url: String,
    override val method: String,
    override val headers: Map<String, String>,
    override val timeoutMs: Long,
    val body: ByteArray? = null,
    val onProgress: ((uploadedBytes: Long) -> Unit)? = null,
) : ProtonDriveHttpBaseRequest

sealed interface ProtonDriveHttpBaseRequest {
    val url: String
    val method: String
    val headers: Map<String, String>

    /** When this timeout is reached, the request should be aborted (mapped to [dev.carlsen.protondrive.sdk.errors.AbortError]). */
    val timeoutMs: Long
}

/** Minimal response abstraction, standing in for the Fetch API's Response used by the JS SDK. */
interface ProtonDriveHttpResponse {
    val status: Int
    val ok: Boolean get() = status in 200..299
    val statusText: String
    val headers: Map<String, String>

    suspend fun json(): JsonElement

    /** Streamed body bytes, used for block download (ports getBlockStream in apiService.ts). */
    suspend fun bodyBytes(): ByteArray
}
