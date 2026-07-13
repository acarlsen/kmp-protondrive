package dev.carlsen.protondrive.sdk.apiService

import dev.carlsen.protondrive.sdk.errors.NodeWithSameNameExistsValidationError
import dev.carlsen.protondrive.sdk.errors.ProtonDriveError
import dev.carlsen.protondrive.sdk.errors.ServerError
import dev.carlsen.protondrive.sdk.errors.UnauthorizedError
import dev.carlsen.protondrive.sdk.errors.ValidationError
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive

/** Ports internal/apiService/errors.ts. */
class APIHTTPError(message: String, statusCode: Int) : ServerError(message, statusCode = statusCode)

class APICodeError(message: String, code: Int, val debug: Any? = null) : ServerError(message, code = code)

class NotFoundAPIError(message: String, code: Int? = null, details: Any? = null) : ValidationError(message, code, details)

class InvalidRequirementsAPIError(message: String, code: Int? = null, details: Any? = null) :
    ValidationError(message, code, details)

/**
 * Builds the appropriate [ServerError]/[ValidationError] subtype from an API
 * response, mirroring apiErrorFactory() in internal/apiService/errors.ts.
 */
fun apiErrorFactory(
    status: Int? = null,
    statusText: String? = null,
    result: JsonElement? = null,
    error: Throwable? = null,
): ProtonDriveError {
    if (status == HTTPErrorCode.UNAUTHORIZED) {
        val obj = result as? JsonObject
        val message = obj?.get("Error")?.jsonPrimitive?.content ?: statusText ?: "Unauthorized"
        val code = obj?.get("Code")?.jsonPrimitive?.intOrNull
        return UnauthorizedError(message, code)
    }

    if (status == HTTPErrorCode.NOT_FOUND || result == null || result is JsonNull) {
        val fallbackMessage = error?.message ?: "Unknown error"
        return APIHTTPError(statusText ?: fallbackMessage, status ?: 500)
    }

    val obj = result as? JsonObject ?: return APIHTTPError(statusText ?: "Unknown error", status ?: 500)

    val code = obj["Code"]?.jsonPrimitive?.intOrNull ?: 0
    val message = obj["Error"]?.jsonPrimitive?.content ?: "Unknown error"
    val details = obj["Details"]

    return when (code) {
        ErrorCode.NOT_EXISTS -> NotFoundAPIError(message, code, details)
        // ValidationError should be used only when it's clearly a user input error,
        // otherwise it should be a ServerError. Specific cases that aren't clear
        // from the code alone must be handled by each module separately.
        ErrorCode.INVALID_REQUIREMENTS -> InvalidRequirementsAPIError(message, code, details)
        // ConflictLinkID identifies the existing node with the same name - callers (e.g. the
        // CLI's upload flow) use it to offer "upload as a new revision instead" without an
        // extra listing round-trip.
        ErrorCode.ALREADY_EXISTS -> NodeWithSameNameExistsValidationError(
            message,
            code,
            existingNodeUid = (details as? JsonObject)?.get("ConflictLinkID")?.jsonPrimitive?.contentOrNull,
        )
        ErrorCode.INVALID_VALUE,
        ErrorCode.NOT_ENOUGH_PERMISSIONS,
        ErrorCode.NOT_ENOUGH_PERMISSIONS_TO_GRANT_PERMISSIONS,
        ErrorCode.INSUFFICIENT_QUOTA,
        ErrorCode.INSUFFICIENT_SPACE,
        ErrorCode.MAX_FILE_SIZE_FOR_FREE_USER,
        ErrorCode.MAX_PUBLIC_EDIT_MODE_FOR_FREE_USER,
        ErrorCode.INSUFFICIENT_VOLUME_QUOTA,
        ErrorCode.INSUFFICIENT_DEVICE_QUOTA,
        ErrorCode.ALREADY_MEMBER_OF_SHARE_IN_VOLUME_WITH_ANOTHER_ADDRESS,
        ErrorCode.TOO_MANY_CHILDREN,
        ErrorCode.NESTING_TOO_DEEP,
        ErrorCode.INSUFFICIENT_INVITATION_QUOTA,
        ErrorCode.INSUFFICIENT_SHARE_QUOTA,
        ErrorCode.INSUFFICIENT_SHARE_JOINED_QUOTA,
        ErrorCode.INSUFFICIENT_BOOKMARKS_QUOTA,
        -> ValidationError(message, code, details)
        else -> APICodeError(message, code, details)
    }
}
