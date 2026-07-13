package dev.carlsen.protondrive.sdk.errors

/**
 * Base class for all SDK errors (ports client/js/src/errors.ts).
 *
 * This class can be used for catching all SDK errors. The error should have a
 * message that can be shown to the user without any modification.
 *
 * No retries should be done as that is already handled by the SDK.
 *
 * When the SDK throws an error and it is not a [ProtonDriveError], it is an
 * unhandled error and usually indicates a bug in the SDK.
 */
open class ProtonDriveError(message: String, cause: Throwable? = null) : Exception(message, cause)

/** Thrown when the operation is aborted (e.g. via a cancelled coroutine). */
open class AbortError(message: String = "Operation aborted") : ProtonDriveError(message)

/**
 * Thrown when validation fails, either client-side or server-side (e.g. not
 * enough permissions, node name doesn't follow the required format, etc).
 */
open class ValidationError(
    message: String,
    val code: Int? = null,
    val details: Any? = null,
) : ProtonDriveError(message)

/**
 * Thrown when a node with the same name already exists in the parent folder.
 * The available name is provided so the caller can offer it to the user.
 */
class NodeWithSameNameExistsValidationError(
    message: String,
    code: Int,
    val existingNodeUid: String? = null,
    val isUnfinishedUpload: Boolean = false,
) : ValidationError(message, code)

/**
 * Thrown when an API call fails. Covers both HTTP errors and API errors. The
 * SDK automatically retries the request before this error is thrown - callers
 * should not retry it again.
 */
open class ServerError(
    message: String,
    val statusCode: Int? = null,
    val code: Int? = null,
) : ProtonDriveError(message)

/** Thrown when the client makes too many requests (HTTP 429). */
class RateLimitedError(message: String) : ServerError(message, code = 429)

/**
 * Thrown when the API rejects the session's credentials (HTTP 401) - the
 * access token is expired or revoked. Callers should attempt
 * [dev.carlsen.protondrive.sdk.auth.ProtonAuth.refreshSession] and retry once,
 * or fall back to a fresh login if there's no refresh token or the refresh
 * itself fails.
 */
class UnauthorizedError(message: String, code: Int? = null) : ServerError(message, statusCode = 401, code = code)

/** Thrown when the client is not connected to the internet. */
class ConnectionError(message: String) : ProtonDriveError(message)

/** Thrown when decryption fails. Should be reported to the user as a bug. */
class DecryptionError(message: String, cause: Throwable? = null) : ProtonDriveError(message, cause)

/** Thrown when a data integrity check fails (e.g. hash mismatch). */
class IntegrityError(message: String, val debug: Any? = null) : ProtonDriveError(message)
