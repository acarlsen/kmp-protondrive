package dev.carlsen.protondrive.sdk.apiService

import dev.carlsen.protondrive.sdk.auth.LoginResult

/**
 * Wraps a real [ProtonDriveHttpClient] so 401 anywhere triggers exactly one transparent
 * refresh-and-retry, with [onRefreshed] given the chance to persist the rotated tokens - this is
 * what lets a long-running session (browsing, uploading, downloading) survive its access token
 * expiring mid-session instead of failing every subsequent request until the host re-logs in.
 * Used internally by [dev.carlsen.protondrive.sdk.ProtonDriveSdk].
 *
 * [refreshing] guards against the refresh call itself (which goes through this same wrapper,
 * since it's just another [DriveAPIService] request) recursing back into another refresh attempt.
 */
class SessionRefreshingHttpClient(
    private val delegate: ProtonDriveHttpClient,
    private val getRefreshToken: () -> String?,
    private val refresh: suspend (refreshToken: String) -> LoginResult,
    private val onRefreshed: (LoginResult) -> Unit,
) : ProtonDriveHttpClient {

    private var refreshing = false

    override suspend fun fetchJson(request: ProtonDriveHttpJsonRequest): ProtonDriveHttpResponse =
        withRefreshOn401 { delegate.fetchJson(request) }

    override suspend fun fetchBlob(request: ProtonDriveHttpBlobRequest): ProtonDriveHttpResponse =
        withRefreshOn401 { delegate.fetchBlob(request) }

    private suspend fun withRefreshOn401(call: suspend () -> ProtonDriveHttpResponse): ProtonDriveHttpResponse {
        val response = call()
        if (response.status != HTTPErrorCode.UNAUTHORIZED || refreshing) return response

        val refreshToken = getRefreshToken() ?: return response
        val refreshed = try {
            refreshing = true
            refresh(refreshToken)
        } catch (_: Exception) {
            null
        } finally {
            refreshing = false
        }
        if (refreshed == null) return response

        onRefreshed(refreshed)
        return call()
    }
}
