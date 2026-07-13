package dev.carlsen.protondrive.sdk.apiService

/** Session credentials a [ProtonDriveHttpClient] attaches to authenticated requests. */
data class ProtonSession(val uid: String, val accessToken: String)
