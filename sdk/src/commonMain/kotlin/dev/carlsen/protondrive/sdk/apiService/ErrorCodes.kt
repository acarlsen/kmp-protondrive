package dev.carlsen.protondrive.sdk.apiService

/** Ports internal/apiService/errorCodes.ts. */
object HTTPErrorCode {
    const val OK = 200
    const val UNAUTHORIZED = 401
    const val NOT_FOUND = 404
    const val TOO_MANY_REQUESTS = 429
    const val INTERNAL_SERVER_ERROR = 500
}

object ErrorCode {
    const val OK = 1000
    const val OK_MANY = 1001
    const val OK_ASYNC = 1002
    const val INVALID_REQUIREMENTS = 2000
    const val INVALID_VALUE = 2001
    const val NOT_ENOUGH_PERMISSIONS = 2011
    const val NOT_ENOUGH_PERMISSIONS_TO_GRANT_PERMISSIONS = 2026

    // Following codes take their name from the API documentation.
    const val ALREADY_EXISTS = 2500
    const val NOT_EXISTS = 2501
    const val INSUFFICIENT_QUOTA = 200001
    const val INSUFFICIENT_SPACE = 200002
    const val MAX_FILE_SIZE_FOR_FREE_USER = 200003
    const val MAX_PUBLIC_EDIT_MODE_FOR_FREE_USER = 200004
    const val INSUFFICIENT_VOLUME_QUOTA = 200100
    const val INSUFFICIENT_DEVICE_QUOTA = 200101
    const val ALREADY_MEMBER_OF_SHARE_IN_VOLUME_WITH_ANOTHER_ADDRESS = 200201
    const val TOO_MANY_CHILDREN = 200300
    const val NESTING_TOO_DEEP = 200301
    const val INSUFFICIENT_INVITATION_QUOTA = 200600
    const val INSUFFICIENT_SHARE_QUOTA = 200601
    const val INSUFFICIENT_SHARE_JOINED_QUOTA = 200602
    const val INSUFFICIENT_BOOKMARKS_QUOTA = 200800
}

fun isCodeOk(code: Int): Boolean = code == ErrorCode.OK || code == ErrorCode.OK_MANY || code == ErrorCode.OK_ASYNC

fun isCodeOkAsync(code: Int): Boolean = code == ErrorCode.OK_ASYNC
