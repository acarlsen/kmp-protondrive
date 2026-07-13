package dev.carlsen.protondrive.sdk.apiService

import java.net.ConnectException
import java.net.UnknownHostException

actual fun isOfflineError(cause: Throwable): Boolean {
    var current: Throwable? = cause
    while (current != null) {
        if (current is UnknownHostException || current is ConnectException) return true
        val next = current.cause
        current = if (next === current) null else next
    }
    return false
}
