package dev.carlsen.protondrive.sdk.testing

import dev.carlsen.protondrive.sdk.apiService.ProtonDriveHttpBlobRequest
import dev.carlsen.protondrive.sdk.apiService.ProtonDriveHttpClient
import dev.carlsen.protondrive.sdk.apiService.ProtonDriveHttpJsonRequest
import dev.carlsen.protondrive.sdk.apiService.ProtonDriveHttpResponse
import kotlinx.serialization.json.JsonElement

class FakeJsonResponse(
    override val status: Int,
    override val statusText: String = "",
    override val headers: Map<String, String> = emptyMap(),
    private val body: JsonElement,
) : ProtonDriveHttpResponse {
    override suspend fun json(): JsonElement = body
    override suspend fun bodyBytes(): ByteArray = error("bodyBytes not used by this fake")
}

/** Queues one action (a response or a thrown exception) per expected call. */
class FakeHttpClient : ProtonDriveHttpClient {
    val jsonRequests = mutableListOf<ProtonDriveHttpJsonRequest>()
    private val queue = ArrayDeque<() -> ProtonDriveHttpResponse>()

    fun enqueueResponse(response: ProtonDriveHttpResponse) {
        queue.addLast { response }
    }

    fun enqueueThrow(exception: Exception) {
        queue.addLast { throw exception }
    }

    override suspend fun fetchJson(request: ProtonDriveHttpJsonRequest): ProtonDriveHttpResponse {
        jsonRequests += request
        val action = queue.removeFirstOrNull() ?: error("No more fake responses queued for ${request.method} ${request.url}")
        return action()
    }

    override suspend fun fetchBlob(request: ProtonDriveHttpBlobRequest): ProtonDriveHttpResponse {
        error("fetchBlob not used by this fake")
    }
}
