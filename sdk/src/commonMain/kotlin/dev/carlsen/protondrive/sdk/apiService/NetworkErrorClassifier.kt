package dev.carlsen.protondrive.sdk.apiService

/**
 * True if [cause] represents an inability to reach the network at all (DNS
 * resolution failure, connection refused) as opposed to a generic transport
 * error - used to distinguish [dev.carlsen.protondrive.sdk.errors.ConnectionError]
 * ("offline", worth retrying indefinitely) from [HttpNetworkError].
 */
expect fun isOfflineError(cause: Throwable): Boolean
